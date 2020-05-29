package vtpm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/server"
	gcev1 "google.golang.org/api/compute/v1"
)

func EncryptBytes(siid *gcev1.ShieldedInstanceIdentity, bytes []byte) (*DecryptionBlob, error) {
	if siid == nil {
		return nil, fmt.Errorf("siid was nil")
	}

	encryptionKey := siid.EncryptionKey

	if encryptionKey == nil {
		return nil, fmt.Errorf("siid.EncryptionKey was nil")
	}

	block, _ := pem.Decode([]byte(encryptionKey.EkPub))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing RSA public key: %q", encryptionKey.EkPub)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %v", err)
	}

	key := make([]byte, symmetricKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}
	blob, err := server.CreateImportBlob(pub, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create RSA import blob: %v", err)
	}
	cypher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create AES cypher: %v", err)
	}
	gcm, err := cipher.NewGCM(cypher)
	if err != nil {
		return nil, fmt.Errorf("could not create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	return &DecryptionBlob{
		SealedKey:  blob,
		Ciphertext: gcm.Seal(bytes[:0], nonce, bytes, nil),
	}, nil
}
