package x509util_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestParseFile(t *testing.T) {
	var (
		keyFile     string
		certFile    string
		privKeyInfo x509util.PrivateKeyInfo
		certs       []*x509.Certificate
		err         error
	)
	assert := assert.New(t)
	password, _ := os.ReadFile("../test/testdata/pki/private/password.txt")
	incorrectPassword := []byte("INCORRECT PASSWORD")

	/*
	 * non-existent file
	 */
	keyFile = "../test/testdata/pki/misc/non-existent.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, nil, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.NotNil(err)

	certFile = "../test/testdata/pki/misc/non-existent.pem"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, nil, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.NotNil(err)

	certFile = "../test/testdata/pki/misc/non-existent.pem"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, nil, true, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.NotNil(err)

	/*
	 * Empty file
	 */
	keyFile = "../test/testdata/pki/misc/empty.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, nil, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.NotNil(err)

	certFile = "../test/testdata/pki/misc/empty.pem"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, nil, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.NotNil(err)

	certFile = "../test/testdata/pki/misc/empty.pem"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, nil, true, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.NotNil(err)

	/*
	 * Invalid format
	 */
	certFile = "../test/testdata/pki/private/server-a-rsa.pem"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, nil, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.NotNil(err)

	/*
	 * Private key
	 */
	keyFile = "../test/testdata/pki/private/server-a-rsa.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, nil, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-rsa-traditional.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, nil, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-rsa-encrypted.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, password, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-rsa-traditional-encrypted.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, password, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-rsa.der"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, nil, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ecdsa.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, nil, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ecdsa-traditional.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, nil, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ecdsa-encrypted.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, password, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ecdsa-traditional-encrypted.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, password, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ecdsa.der"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, nil, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ed25519.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, nil, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ed25519-encrypted.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, password, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ed25519.der"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, nil, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	/*
	 * Private key with an incorrect password
	 */
	keyFile = "../test/testdata/pki/private/server-a-rsa-encrypted.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, incorrectPassword, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Error(err, "no private key")

	keyFile = "../test/testdata/pki/private/server-a-rsa-traditional-encrypted.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, incorrectPassword, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Error(err, "no private key")

	keyFile = "../test/testdata/pki/private/server-a-ecdsa-encrypted.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, incorrectPassword, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Error(err, "no private key")

	keyFile = "../test/testdata/pki/private/server-a-ecdsa-traditional-encrypted.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, incorrectPassword, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Error(err, "no private key")

	keyFile = "../test/testdata/pki/private/server-a-ed25519-encrypted.pem"
	privKeyInfo, certs, err = x509util.ParseFile(keyFile, incorrectPassword, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Error(err, "no private key")

	/*
	 * Certificate
	 */
	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.pem"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, nil, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.der"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, nil, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.p7b"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, nil, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa-der.p7b"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, nil, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.p12"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, password, true, true)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.pfx"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, password, true, true)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	// no EOL
	certFile = "../test/testdata/pki/cert/valid/misc-no-eol.pem"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, nil, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	// Explanatory Text
	certFile = "../test/testdata/pki/cert/valid/misc-explanatory-text.pem"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, nil, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	/*
	 * Certificate with incorrect password
	 */
	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.p12"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, incorrectPassword, true, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Error(err, "no valid certificate")

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.pfx"
	privKeyInfo, certs, err = x509util.ParseFile(certFile, incorrectPassword, true, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Error(err, "no valid certificate")
}

func TestParseDER(t *testing.T) {
	var (
		keyFile     string
		certFile    string
		data        []byte
		privKeyInfo x509util.PrivateKeyInfo
		certs       []*x509.Certificate
		err         error
	)
	assert := assert.New(t)
	password, _ := os.ReadFile("../test/testdata/pki/private/password.txt")
	incorrectPassword := []byte("INCORRECT PASSWORD")

	/*
	 * Empty file
	 */
	keyFile = "../test/testdata/pki/misc/empty.pem"
	data, _ = os.ReadFile(keyFile)
	privKeyInfo, _, err = x509util.ParseDER(data, []byte{}, keyFile, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	certFile = "../test/testdata/pki/misc/empty.pem"
	data, _ = os.ReadFile(certFile)
	_, certs, err = x509util.ParseDER(data, []byte{}, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	certFile = "../test/testdata/pki/misc/empty.pem"
	data, _ = os.ReadFile(certFile)
	_, certs, err = x509util.ParseDER(data, []byte{}, certFile, true, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	/*
	 * Invalid format
	 */
	keyFile = "../test/testdata/pki/cert/valid/server-a-rsa.der"
	data, _ = os.ReadFile(keyFile)
	privKeyInfo, certs, err = x509util.ParseDER(data, []byte{}, keyFile, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-rsa.pem"
	data, _ = os.ReadFile(keyFile)
	privKeyInfo, certs, err = x509util.ParseDER(data, []byte{}, keyFile, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	certFile = "../test/testdata/pki/private/server-a-rsa.der"
	data, _ = os.ReadFile(certFile)
	privKeyInfo, certs, err = x509util.ParseDER(data, []byte{}, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.pem"
	data, _ = os.ReadFile(certFile)
	privKeyInfo, certs, err = x509util.ParseDER(data, []byte{}, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.p7b"
	data, _ = os.ReadFile(certFile)
	privKeyInfo, certs, err = x509util.ParseDER(data, []byte{}, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	/*
	 * Private key
	 */
	keyFile = "../test/testdata/pki/private/server-a-rsa.der"
	data, _ = os.ReadFile(keyFile)
	privKeyInfo, certs, err = x509util.ParseDER(data, []byte{}, keyFile, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ecdsa.der"
	data, _ = os.ReadFile(keyFile)
	privKeyInfo, certs, err = x509util.ParseDER(data, []byte{}, keyFile, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ed25519.der"
	data, _ = os.ReadFile(keyFile)
	privKeyInfo, certs, err = x509util.ParseDER(data, []byte{}, keyFile, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	/*
	 * Certificate
	 */
	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.der"
	data, _ = os.ReadFile(certFile)
	privKeyInfo, certs, err = x509util.ParseDER(data, []byte{}, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa-der.p7b"
	data, _ = os.ReadFile(certFile)
	privKeyInfo, certs, err = x509util.ParseDER(data, []byte{}, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.p12"
	data, _ = os.ReadFile(certFile)
	privKeyInfo, certs, err = x509util.ParseDER(data, password, certFile, true, true)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	/*
	 * Certificate with an incorrect password
	 */
	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.p12"
	data, _ = os.ReadFile(certFile)
	privKeyInfo, certs, err = x509util.ParseDER(data, incorrectPassword, certFile, true, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)
}

func TestParsePEMWithCertificate(t *testing.T) {
	var (
		keyFile     string
		certFile    string
		data        []byte
		blocks      []*pem.Block
		privKeyInfo x509util.PrivateKeyInfo
		certs       []*x509.Certificate
		err         error
	)
	assert := assert.New(t)
	password, _ := os.ReadFile("../test/testdata/pki/private/password.txt")
	incorrectPassword := []byte("INCORRECT PASSWORD")

	/*
	 * Empty file
	 */
	keyFile = "../test/testdata/pki/misc/empty.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, keyFile, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	certFile = "../test/testdata/pki/misc/empty.pem"
	data, _ = os.ReadFile(certFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	certFile = "../test/testdata/pki/misc/empty.pem"
	data, _ = os.ReadFile(certFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, certFile, true, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	/*
	 * Invalid format
	 */
	keyFile = "../test/testdata/pki/cert/valid/server-a-rsa.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, keyFile, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-rsa.der"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, keyFile, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	certFile = "../test/testdata/pki/private/server-a-rsa.pem"
	data, _ = os.ReadFile(certFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.der"
	data, _ = os.ReadFile(certFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa-der.p7b"
	data, _ = os.ReadFile(certFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.p12"
	data, _ = os.ReadFile(certFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	/*
	 * Private key
	 */
	keyFile = "../test/testdata/pki/private/server-a-rsa.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, keyFile, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-rsa-traditional.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, keyFile, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-rsa-encrypted.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, password, keyFile, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-rsa-traditional-encrypted.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, password, keyFile, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ecdsa.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, keyFile, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ecdsa-traditional.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, keyFile, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ecdsa-encrypted.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, password, keyFile, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ecdsa-traditional-encrypted.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, password, keyFile, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ed25519.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, keyFile, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	keyFile = "../test/testdata/pki/private/server-a-ed25519-encrypted.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, password, keyFile, true, false)
	assert.NotEmpty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.Nil(err)

	/*
	 * Private key with an incorrect password
	 */
	keyFile = "../test/testdata/pki/private/server-a-rsa-encrypted.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, incorrectPassword, keyFile, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.NotNil(err)

	keyFile = "../test/testdata/pki/private/server-a-rsa-traditional-encrypted.pem"
	data, _ = os.ReadFile(keyFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, incorrectPassword, keyFile, true, false)
	assert.Empty(privKeyInfo.Key)
	assert.Empty(certs)
	assert.NotNil(err)

	/*
	 * Certificate
	 */
	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.pem"
	data, _ = os.ReadFile(certFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-rsa.p7b"
	data, _ = os.ReadFile(certFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-ecdsa.pem"
	data, _ = os.ReadFile(certFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)

	certFile = "../test/testdata/pki/cert/valid/server-a-ed25519.pem"
	data, _ = os.ReadFile(certFile)
	blocks = x509util.ExtractPEMBlocks(data)
	privKeyInfo, certs, err = x509util.ParsePEMBlocks(blocks, nil, certFile, false, true)
	assert.Empty(privKeyInfo.Key)
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Nil(err)
}
