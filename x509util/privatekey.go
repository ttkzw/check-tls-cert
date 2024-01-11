// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/youmark/pkcs8"
	_ "golang.org/x/crypto/pbkdf2"
	_ "golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// PrivateKeyInfo describes the information of a private key.
type PrivateKeyInfo struct {
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	Key                interface{}
}

// ParsePrivateKeyFile parses a private key file in PEM format and returns a private key.
func ParsePrivateKeyFile(keyFile string, password []byte) (privKeyInfo PrivateKeyInfo, err error) {
	privKeyInfo, _, err = ParseFile(keyFile, password, true, false)
	if err != nil {
		return
	}

	if privKeyInfo.Key == nil {
		err = errors.New("no valid private key")
	}
	return
}

func ParsePrivateKeyPEMBlock(block *pem.Block, isEncrypted bool, password []byte) (privKeyInfo PrivateKeyInfo, err error) {
	var der = block.Bytes

	switch block.Type {
	case "RSA PRIVATE KEY":
		if isEncrypted {
			//lint:ignore SA1019 Encrypted PEM files are still used.
			if der, err = x509.DecryptPEMBlock(block, password); err != nil {
				return
			}
		}
		privKeyInfo, err = parsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		if isEncrypted {
			//lint:ignore SA1019 Encrypted PEM files are still used.
			if der, err = x509.DecryptPEMBlock(block, password); err != nil {
				return
			}
		}
		privKeyInfo, err = parseECPrivateKey(der)
	case "PRIVATE KEY":
		privKeyInfo, err = parsePKCS8PrivateKey(der, false, nil)
	case "ENCRYPTED PRIVATE KEY":
		privKeyInfo, err = parsePKCS8PrivateKey(der, true, password)
	default:
		err = errors.New("private key: unknown type")
	}

	return
}

func ParsePrivateKey(der []byte) (privKeyInfo PrivateKeyInfo, err error) {
	privKeyInfo, err = parsePKCS1PrivateKey(der)
	if err == nil {
		return
	}

	privKeyInfo, err = parseECPrivateKey(der)
	if err == nil {
		return
	}

	privKeyInfo, err = parsePKCS8PrivateKey(der, false, nil)
	if err == nil {
		return
	}

	return privKeyInfo, nil
}

func parsePKCS1PrivateKey(der []byte) (privKeyInfo PrivateKeyInfo, err error) {
	var privKey *rsa.PrivateKey
	if privKey, err = x509.ParsePKCS1PrivateKey(der); err != nil {
		return
	}

	privKeyInfo = PrivateKeyInfo{
		PublicKeyAlgorithm: x509.RSA,
		Key:                privKey,
	}
	return
}

func parseECPrivateKey(der []byte) (privKeyInfo PrivateKeyInfo, err error) {
	var privKey *ecdsa.PrivateKey
	if privKey, err = x509.ParseECPrivateKey(der); err != nil {
		return
	}

	privKeyInfo = PrivateKeyInfo{
		PublicKeyAlgorithm: x509.ECDSA,
		Key:                privKey,
	}
	return
}

func parsePKCS8PrivateKey(der []byte, isEncrypted bool, password []byte) (privKeyInfo PrivateKeyInfo, err error) {
	var (
		privKey interface{}
		algo    x509.PublicKeyAlgorithm
	)

	if isEncrypted {
		if privKey, err = pkcs8.ParsePKCS8PrivateKey(der, password); err != nil {
			return
		}
	} else {
		if privKey, err = x509.ParsePKCS8PrivateKey(der); err != nil {
			return
		}

	}

	switch privKey.(type) {
	case *rsa.PrivateKey:
		algo = x509.RSA
	case *ecdsa.PrivateKey:
		algo = x509.ECDSA
	case ed25519.PrivateKey:
		algo = x509.Ed25519
	default:
		// If the public key algorithm is unknown, ParsePKCS8PrivateKey() will fail and it will not reach here.
		//lint:ignore ST1005 "Private Key" is a component name.
		err = errors.New("Private Key: unknown public key algorithm")
	}

	privKeyInfo = PrivateKeyInfo{
		PublicKeyAlgorithm: algo,
		Key:                privKey,
	}
	return
}

// ReadPasswordFile reads the password from the password file.
func ReadPasswordFile(passwordFile string) ([]byte, error) {
	password, err := os.ReadFile(passwordFile)
	if err != nil {
		return nil, err
	}

	password = bytes.TrimRight(password, "\n\r")
	return password, nil
}

func readPassword(keyFile string) (password []byte, err error) {
	for len(password) == 0 {
		fmt.Printf("Enter password for %s: ", keyFile)
		password, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, err
		}
		if len(password) > 0 {
			break
		}
		fmt.Println("Error: password is empty")
	}
	return password, nil
}
