package vtpm

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

func OpenVTPM(vtpmPath string) (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM(vtpmPath)
}

func DecryptBytes(vtpmRWC io.ReadWriteCloser, blob *DecryptionBlob) ([]byte, error) {
	ek, err := tpm2tools.EndorsementKeyRSA(vtpmRWC)
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM's RSA Endorsement Key: %v", err)
	}
	defer ek.Close()

	key, err := ek.Import(vtpmRWC, blob.SealedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt import blob: %v", err)
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create cypher: %v", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("could not create GCM: %v", err)
	}

	nonce := blob.Ciphertext[:gcm.NonceSize()]
	payload := blob.Ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, payload, nil)
}
