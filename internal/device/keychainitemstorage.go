package device

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	bolt "go.etcd.io/bbolt"
)

func (kci *KeychainItem) boltKey() string {
	return strings.Join([]string{kci.Keychain.ID, kci.Keychain.Type, kci.UUID}, "_")
}

// Save writes a keychain item to a keychain's BoltDB.
func (kci *KeychainItem) Save() error {
	return kci.Keychain.DB.Update(kci.save)
}

func (kci *KeychainItem) save(tx *bolt.Tx) error {
	if err := kci.encode(); err != nil {
		return err
	}
	if err := BucketPutOrDelete(tx, "keychain_items_item", kci.boltKey(), kci.Item); err != nil {
		return err
	}
	return BucketPutOrDeleteInt(tx, "keychain_item_class", kci.boltKey(), kci.Class)
}

func (kci *KeychainItem) Delete() error {
	return kci.Keychain.DB.Update(func(tx *bolt.Tx) error {
		err := BucketPutOrDelete(tx, "keychain_items_item", kci.boltKey(), nil)
		if err != nil {
			return err
		}
		return BucketPutOrDeleteInt(tx, "keychain_item_class", kci.boltKey(), 0)
	})
}

// LoadKeychainItem loads a *KeychainItem from a keychain's BoltDB.
func LoadKeychainItem(kc *Keychain, uuid string) (kci *KeychainItem, err error) {
	kci = &KeychainItem{
		Keychain: kc,
		UUID:     uuid,
	}
	err = kc.DB.View(func(tx *bolt.Tx) error {
		kci.Item = append([]byte(nil), BucketGet(tx, "keychain_items_item", kci.boltKey())...)
		if len(kci.Item) == 0 {
			return errors.New("empty keychain item")
		}
		kci.Class = BucketGetInt(tx, "keychain_item_class", kci.boltKey())
		if kci.Class == 0 {
			return errors.New("invalid keychain item class 0")
		}
		return nil
	})
	if err != nil {
		return
	}
	err = kci.decode()
	return
}

func (kc *Keychain) loadIdentity(uuid string) (*x509.Certificate, *rsa.PrivateKey, error) {
	if uuid == "" {
		return nil, nil, errors.New("device has no MDM identity")
	}
	identity, err := LoadKeychainItem(kc, uuid)
	if err != nil {
		return nil, nil, fmt.Errorf("loading identity: %w", err)
	}
	if identity.Class != ClassIdentity {
		return nil, nil, errors.New("invalid keychain identity")
	}
	key, err := LoadKeychainItem(kc, identity.IdentityKeyUUID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading identity key: %w", err)
	}
	cert, err := LoadKeychainItem(kc, identity.IdentityCertificateUUID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading identity certificate: %w", err)
	}
	if key.Key == nil || cert.Certificate == nil {
		return nil, nil, errors.New("incomplete keychain identity")
	}
	return cert.Certificate, key.Key, nil
}
