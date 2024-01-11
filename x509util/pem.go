// Copyright 2021-2022 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"crypto/x509"
	"encoding/pem"
)

func ExtractPEMBlocks(data []byte) []*pem.Block {
	var blocks []*pem.Block
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		data = rest
		if block == nil {
			break
		}
		if block.Type == "" {
			continue
		}
		blocks = append(blocks, block)
	}
	return blocks
}

func IsPrivateKeyPEMBlock(block *pem.Block) bool {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return true
	case "EC PRIVATE KEY":
		return true
	case "PRIVATE KEY":
		return true
	case "ENCRYPTED PRIVATE KEY":
		return true
	default:
	}
	return false
}

func IsCertificatePEMBlock(block *pem.Block) bool {
	switch block.Type {
	case "CERTIFICATE":
		return true
	case "PKCS7":
		return true
	default:
	}
	return false
}

func IsEncryptedPEMBlock(block *pem.Block) bool {
	switch block.Type {
	case "RSA PRIVATE KEY":
		//lint:ignore SA1019 Encrypted PEM files are still used.
		return x509.IsEncryptedPEMBlock(block)
	case "EC PRIVATE KEY":
		//lint:ignore SA1019 Encrypted PEM files are still used.
		return x509.IsEncryptedPEMBlock(block)
	case "PRIVATE KEY":
		return false
	case "ENCRYPTED PRIVATE KEY":
		return true
	default:
	}

	return false
}
