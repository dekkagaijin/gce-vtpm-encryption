// Package vtpm contains utilities for encryption leveraging GCE Shielded Instance vTPM
package vtpm

import (
	tpmpb "github.com/google/go-tpm-tools/proto"
)

const symmetricKeySize = 32

type DecryptionBlob struct {
	SealedKey  *tpmpb.ImportBlob
	Ciphertext []byte
}
