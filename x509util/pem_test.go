// Copyright 2022 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util_test

import (
	"encoding/pem"
	"os"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestExtractPEMBlocks(t *testing.T) {
	var (
		data   []byte
		err    error
		blocks []*pem.Block
	)
	assert := assert.New(t)

	// PEM: RSA PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa-traditional.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.Equal("RSA PRIVATE KEY", blocks[0].Type)

	// PEM: EC PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-ecdsa-traditional.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.Equal("EC PRIVATE KEY", blocks[0].Type)

	// PEM: PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.Equal("PRIVATE KEY", blocks[0].Type)

	// PEM: PRIVATE KEY
	// no EOL
	data, err = os.ReadFile("../test/testdata/pki/private/misc-no-eol.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.Equal("PRIVATE KEY", blocks[0].Type)

	// PEM: PRIVATE KEY
	// Explanatory Text
	data, err = os.ReadFile("../test/testdata/pki/private/misc-explanatory-text.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.Equal("PRIVATE KEY", blocks[0].Type)

	// PEM: ENCRYPTED PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa-encrypted.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.Equal("ENCRYPTED PRIVATE KEY", blocks[0].Type)

	// PEM: CERTIFICATE
	data, err = os.ReadFile("../test/testdata/pki/cert/valid/server-a-rsa.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.Equal("CERTIFICATE", blocks[0].Type)

	// PEM: CERTIFICATE
	// no EOL
	data, err = os.ReadFile("../test/testdata/pki/cert/valid/misc-no-eol.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.Equal("CERTIFICATE", blocks[0].Type)

	// PEM: CERTIFICATE
	// Explanatory Text
	data, err = os.ReadFile("../test/testdata/pki/cert/valid/misc-explanatory-text.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.Equal("CERTIFICATE", blocks[0].Type)

	// PEM: PKCS7
	data, err = os.ReadFile("../test/testdata/pki/cert/valid/server-a-rsa.p7b")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.Equal("PKCS7", blocks[0].Type)

	// DER
	data, err = os.ReadFile("../test/testdata/pki/cert/valid/server-a-rsa.der")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.Empty(blocks)

	// PEM: CERTIFICATE chain
	data, err = os.ReadFile("../test/testdata/pki/chain/fullchain-a-rsa.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.Equal("CERTIFICATE", blocks[0].Type)
	assert.Equal("CERTIFICATE", blocks[1].Type)
}

func TestIsPrivateKeyPEMBlock(t *testing.T) {
	var (
		data   []byte
		blocks []*pem.Block
		err    error
	)
	assert := assert.New(t)

	// PEM: RSA PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa-traditional.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.True(x509util.IsPrivateKeyPEMBlock(blocks[0]))

	// PEM: EC PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-ecdsa-traditional.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.True(x509util.IsPrivateKeyPEMBlock(blocks[0]))

	// PEM: PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.True(x509util.IsPrivateKeyPEMBlock(blocks[0]))

	// PEM: ENCRYPTED PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa-encrypted.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.True(x509util.IsPrivateKeyPEMBlock(blocks[0]))

	// PEM: CERTIFICATE
	data, err = os.ReadFile("../test/testdata/pki/cert/valid/server-a-rsa.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.False(x509util.IsPrivateKeyPEMBlock(blocks[0]))

	// PEM: PKCS7
	data, err = os.ReadFile("../test/testdata/pki/cert/valid/server-a-rsa.p7b")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.False(x509util.IsPrivateKeyPEMBlock(blocks[0]))
}

func TestIsCertificatePEMBlock(t *testing.T) {
	var (
		data   []byte
		blocks []*pem.Block
		err    error
	)
	assert := assert.New(t)

	// PEM: CERTIFICATE
	data, err = os.ReadFile("../test/testdata/pki/cert/valid/server-a-rsa.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.True(x509util.IsCertificatePEMBlock(blocks[0]))

	// PEM: PKCS7
	data, err = os.ReadFile("../test/testdata/pki/cert/valid/server-a-rsa.p7b")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.True(x509util.IsCertificatePEMBlock(blocks[0]))

	// PEM: RSA PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa-traditional.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.False(x509util.IsCertificatePEMBlock(blocks[0]))

	// PEM: EC PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-ecdsa-traditional.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.False(x509util.IsCertificatePEMBlock(blocks[0]))

	// PEM: PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.False(x509util.IsCertificatePEMBlock(blocks[0]))

	// PEM: ENCRYPTED PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa-encrypted.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.False(x509util.IsCertificatePEMBlock(blocks[0]))
}

func TestIsEncryptedPEMBlock(t *testing.T) {
	var (
		data   []byte
		blocks []*pem.Block
		err    error
	)
	assert := assert.New(t)

	// PEM: RSA PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa-traditional.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.False(x509util.IsEncryptedPEMBlock(blocks[0]))

	// PEM: RSA PRIVATE KEY (encrypted)
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa-traditional-encrypted.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.True(x509util.IsEncryptedPEMBlock(blocks[0]))

	// PEM: EC PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-ecdsa-traditional.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.False(x509util.IsEncryptedPEMBlock(blocks[0]))

	// PEM: EC PRIVATE KEY (encrypted)
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-ecdsa-traditional-encrypted.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.True(x509util.IsEncryptedPEMBlock(blocks[0]))

	// PEM: PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.False(x509util.IsEncryptedPEMBlock(blocks[0]))

	// PEM: ENCRYPTED PRIVATE KEY
	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa-encrypted.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.True(x509util.IsEncryptedPEMBlock(blocks[0]))

	// PEM: CERTIFICATE
	data, err = os.ReadFile("../test/testdata/pki/cert/valid/server-a-rsa.pem")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.False(x509util.IsEncryptedPEMBlock(blocks[0]))

	// PEM: PKCS7
	data, err = os.ReadFile("../test/testdata/pki/cert/valid/server-a-rsa.p7b")
	assert.Nil(err)
	blocks = x509util.ExtractPEMBlocks(data)
	assert.False(x509util.IsEncryptedPEMBlock(blocks[0]))
}
