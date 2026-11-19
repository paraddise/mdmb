package device

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

type Certificate struct {
	UUID        string
	X509        *x509.Certificate
	MDMIdentity bool
	IsIdentity  bool
	Managed     bool
}

// Certificates lists public certificates in the device's System keychain.
func (d *Device) Certificates() ([]Certificate, error) {
	kc := d.SystemKeychain()
	var certificates []Certificate
	err := kc.DB.View(func(tx *bolt.Tx) error {
		var activeCertificate string
		if active := BucketGetString(tx, "device_mdm_identity_keychain_uuid", d.UDID); active != "" {
			item := &KeychainItem{Keychain: kc, UUID: active, Class: ClassIdentity}
			item.Item = BucketGet(tx, "keychain_items_item", item.boltKey())
			if item.decode() == nil {
				activeCertificate = item.IdentityCertificateUUID
			}
		}

		prefix := kc.ID + "_" + kc.Type + "_"
		ids := BucketGetKeysWithPrefix(tx, "keychain_item_class", prefix, true)
		identities := map[string]bool{}
		for _, id := range ids {
			if BucketGetInt(tx, "keychain_item_class", prefix+id) == ClassIdentity {
				item := &KeychainItem{Class: ClassIdentity, Item: BucketGet(tx, "keychain_items_item", prefix+id)}
				if item.decode() == nil && BucketGetInt(tx, "keychain_item_class", prefix+item.IdentityKeyUUID) == ClassKey &&
					len(BucketGet(tx, "keychain_items_item", prefix+item.IdentityKeyUUID)) > 0 {
					identities[item.IdentityCertificateUUID] = true
				}
			}
		}
		for _, id := range ids {
			if BucketGetInt(tx, "keychain_item_class", prefix+id) != ClassCertificate {
				continue
			}
			cert, err := x509.ParseCertificate(bytes.Clone(BucketGet(tx, "keychain_items_item", prefix+id)))
			if err != nil {
				return fmt.Errorf("certificate %s: %w", id, err)
			}
			certificates = append(certificates, Certificate{UUID: id, X509: cert, MDMIdentity: id == activeCertificate, IsIdentity: identities[id],
				Managed: BucketGetString(tx, managedCertificateBucket, prefix+id) == "1"})
		}
		return nil
	})
	sort.SliceStable(certificates, func(i, j int) bool {
		return certificates[i].Name() < certificates[j].Name()
	})
	return certificates, err
}

func (c Certificate) Name() string {
	if cn := c.X509.Subject.CommonName; cn != "" {
		return cn
	}
	if subject := c.X509.Subject.String(); subject != "" {
		return subject
	}
	return c.UUID
}

func (c Certificate) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.X509.Raw})
}

func (c Certificate) Text() string {
	cert := c.X509
	var usages []string
	for i, name := range []string{"Digital signature", "Content commitment", "Key encipherment",
		"Data encipherment", "Key agreement", "Certificate signing", "CRL signing", "Encipher only", "Decipher only"} {
		if cert.KeyUsage&(1<<i) != 0 {
			usages = append(usages, name)
		}
	}
	var extended []string
	for _, usage := range cert.ExtKeyUsage {
		names := [...]string{"Any", "Server authentication", "Client authentication", "Code signing",
			"Email protection", "IPsec end system", "IPsec tunnel", "IPsec user", "Time stamping",
			"OCSP signing", "Microsoft server-gated crypto", "Netscape server-gated crypto",
			"Microsoft commercial code signing", "Microsoft kernel code signing"}
		if usage >= 0 && int(usage) < len(names) {
			extended = append(extended, names[usage])
		} else {
			extended = append(extended, fmt.Sprint(usage))
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		extended = append(extended, oid.String())
	}
	return fmt.Sprintf("Subject: %s\nIssuer: %s\nSerial number: %X\nNot before: %s\nNot after: %s\nSignature algorithm: %s\nPublic key algorithm: %s\nKey usage: %s\nExtended key usage: %s\nSHA-256 fingerprint: %X\n",
		cert.Subject, cert.Issuer, cert.SerialNumber, cert.NotBefore.UTC().Format(time.RFC3339),
		cert.NotAfter.UTC().Format(time.RFC3339), cert.SignatureAlgorithm, cert.PublicKeyAlgorithm,
		strings.Join(usages, ", "), strings.Join(extended, ", "), sha256.Sum256(cert.Raw))
}
