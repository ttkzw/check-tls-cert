// Copyright 2023 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"crypto/x509"
	"fmt"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

// ParseCertificateFiles parses certifcate files and returns certificates.
func ParseCertificateFiles(certFiles ...string) (certs []*x509.Certificate, err error) {
	for _, certFile := range certFiles {
		if certFile == "" {
			continue
		}

		_, c, err := x509util.ParseFile(certFile, nil, false, true)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c...)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates")
	}

	return certs, nil
}
