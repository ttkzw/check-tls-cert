package x509util

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func ParseFile(file string, password []byte, isPrivateKey, isCertificate bool) (privKeyInfo PrivateKeyInfo, certs []*x509.Certificate, err error) {
	var data []byte

	if file == "" {
		return privKeyInfo, certs, fmt.Errorf("filename was not specified")
	}

	data, err = os.ReadFile(file)
	if err != nil {
		return privKeyInfo, certs, err
	}

	blocks := ExtractPEMBlocks(data)
	if len(blocks) > 0 {
		privKeyInfo, certs, err = ParsePEMBlocks(blocks, password, file, isPrivateKey, isCertificate)
	} else {
		privKeyInfo, certs, err = ParseDER(data, password, file, isPrivateKey, isCertificate)
	}

	if isCertificate {
		if len(certs) == 0 {
			return privKeyInfo, certs, fmt.Errorf("no certificate")
		}
	}

	if isPrivateKey {
		if privKeyInfo.Key == nil {
			return privKeyInfo, certs, fmt.Errorf("no private key")
		}
	}

	return
}

func ParseDER(der, password []byte, file string, isPrivateKey, isCertificate bool) (privKeyInfo PrivateKeyInfo, certs []*x509.Certificate, err error) {
	if len(der) == 0 {
		return
	}

	if isPrivateKey {
		privKeyInfo, err = ParsePrivateKey(der)
		if err != nil {
			return
		}
	}

	if isCertificate {
		privKeyInfo, certs, err = ParseCertificate(der, password, file)
		if err != nil {
			return
		}
	}

	return privKeyInfo, certs, nil
}

func ParsePEMBlocks(blocks []*pem.Block, password []byte, file string, isPrivateKey, isCertificate bool) (privKeyInfo PrivateKeyInfo, certs []*x509.Certificate, err error) {
	for _, block := range blocks {
		if isPrivateKey && IsPrivateKeyPEMBlock(block) {
			isEncrypted := IsEncryptedPEMBlock(block)
			if isEncrypted {
				if len(password) == 0 {
					password, err = readPassword(file)
					if err != nil {
						return privKeyInfo, nil, err
					}
				}
			}
			privKeyInfo, err = ParsePrivateKeyPEMBlock(block, isEncrypted, password)
			if err != nil {
				return privKeyInfo, nil, err
			}
		}
		if isCertificate && IsCertificatePEMBlock(block) {
			tmpCerts, err := ParseCertificatePEMBlock(block)
			if err != nil {
				return privKeyInfo, nil, err
			}
			certs = append(certs, tmpCerts...)
		}
	}
	return privKeyInfo, certs, nil
}
