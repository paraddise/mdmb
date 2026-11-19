package device

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// JamfFrameworkIdentity is a provisioned Jamf Management Framework signing identity.
type JamfFrameworkIdentity struct {
	certificate *x509.Certificate
	key         *rsa.PrivateKey
}

func LoadJamfFrameworkIdentity(certPath, keyPath string) (*JamfFrameworkIdentity, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading Jamf Framework certificate: %w", err)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading Jamf Framework key: %w", err)
	}
	if _, err := x509.ParseCertificate(certData); err == nil {
		certData = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certData})
	}
	pair, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, fmt.Errorf("loading Jamf Framework identity: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing Jamf Framework certificate: %w", err)
	}
	key, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("Jamf Framework identity requires an RSA key")
	}
	return &JamfFrameworkIdentity{certificate: cert, key: key}, nil
}

func (identity *JamfFrameworkIdentity) ValidateDevice(udid string) error {
	if identity == nil {
		return errors.New("refresh requires a registered Jamf Framework identity (see tui -h)")
	}
	if !strings.EqualFold(identity.certificate.Subject.CommonName, udid) {
		return errors.New("Jamf Framework certificate does not match this device UDID")
	}
	now := time.Now()
	if now.Before(identity.certificate.NotBefore) || now.After(identity.certificate.NotAfter) {
		return errors.New("Jamf Framework certificate is outside its validity period")
	}
	return nil
}
