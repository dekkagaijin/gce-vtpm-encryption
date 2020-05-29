package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/dekkagaijin/gce-vtpm-encryption/pkg/vtpm"
)

var (
	tpmPath = flag.String("tpm_path", "/dev/tpm0", "path to the TPM device")
	input   = flag.String("input_path", "", "path to the file containing the data to decrypt")
	output  = flag.String("output_path", "", "path to the file to output the decrypted data")
)

func main() {
	flag.Parse()

	if *tpmPath == "" {
		fmt.Fprintln(os.Stderr, "Must specify the --tpm_path flag.")
		os.Exit(1)
	}

	if err := decrypt(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

func decrypt() error {
	tpm, err := vtpm.OpenVTPM(*tpmPath)
	if err != nil {
		return err
	}
	defer tpm.Close()

	inFile := os.Stdin
	if *input != "" {
		if inFile, err = os.Open(*input); err != nil {
			return err
		}
		defer inFile.Close()
	}

	outFile := os.Stdout
	if *output != "" {
		if outFile, err = os.Create(*output); err != nil {
			return err
		}
		defer outFile.Close()
	}

	raw, err := ioutil.ReadAll(inFile)
	if err != nil {
		return fmt.Errorf("could not read input file: %v", err)
	}

	decryptionBlob := &vtpm.DecryptionBlob{}
	if err := json.Unmarshal(raw, decryptionBlob); err != nil {
		return fmt.Errorf("failed to parse DecryptionBlob json: %v", err)
	}

	payload, err := vtpm.DecryptBytes(tpm, decryptionBlob)
	if err != nil {
		return fmt.Errorf("vtpm decryption operation failed: %v", err)
	}

	if _, err := outFile.Write(payload); err != nil {
		return fmt.Errorf("failed to write to output file: %v", err)
	}
	outFile.Sync()

	return nil
}
