package main

import (
	"time"
	"crypto/x509"
	"math/big"
	"crypto/x509/pkix"
	"log"
	"encoding/asn1"
	"net"
	"crypto/rsa"
	"os"
	"encoding/pem"
	"crypto/rand"
)

var notBefore = time.Date(2010, time.January, 1, 0, 0, 0, 0, time.UTC)
var notAfter = time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC)

type generalSubtree struct {
	Name string `asn1:"tag:2,optional,ia5"`
}

type nameConstraints struct {
	Permitted []generalSubtree `asn1:"optional,tag:0"`
	Excluded  []generalSubtree `asn1:"optional,tag:1"`
}

func write(blockType, path string, bytes []byte) {
	out, err := os.Create(path)
	if err != nil {
		log.Fatalf("Could no create %s: %s", path, err)
	}
	err = pem.Encode(out, &pem.Block{Type: blockType, Bytes: bytes})
	if err != nil {
		log.Fatalf("Could no write into %s: %s", path, err)
	}
}

func writePrivateKey(path string, key *rsa.PrivateKey) {
	write("RSA PRIVATE KEY", path, x509.MarshalPKCS1PrivateKey(key))
}

func writeCertificate(path string, cert []byte) {
	write("CERTIFICATE", path, cert)
}

func makeKey() *rsa.PrivateKey {
	res, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Could not generate RSA: %s", err)
	}
	return res
}

func main() {
	caNameConstraints, err := asn1.Marshal(nameConstraints{Permitted: []generalSubtree{{Name: "localhost"}}})
	if err != nil {
		log.Fatalf("Could not serialize name constraints: %s", err)
	}

	caTemplate := x509.Certificate{
		Subject:               pkix.Name{Organization: []string{"localcert.org"}, CommonName: "localcert.org 1"},
		SerialNumber:          big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		MaxPathLenZero:        true,
		MaxPathLen:            0,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{{
			Id:       []int{2, 5, 29, 30},
			Critical: true,
			Value:    caNameConstraints,
		}},
	}
	caKey := makeKey()
	caCert, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, caKey.Public(), caKey)
	if err != nil {
		log.Fatalf("Could not create CA: %s", err)
	}

	localhostCertTemplate := x509.Certificate{
		Subject:               pkix.Name{CommonName: "localhost"},
		SerialNumber:          big.NewInt(2),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	localhostKey := makeKey()
	localhostCert, err := x509.CreateCertificate(rand.Reader, &localhostCertTemplate, &caTemplate, localhostKey.Public(), caKey)
	if err != nil {
		log.Fatalf("Could not create localhost cert: %s", err)
	}

	badTemplate := x509.Certificate{
		Subject:               pkix.Name{CommonName: "bad"},
		SerialNumber:          big.NewInt(3),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{"bad"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	badKey := makeKey()
	badCert, err := x509.CreateCertificate(rand.Reader, &badTemplate, &caTemplate, badKey.Public(), caKey)
	if err != nil {
		log.Fatalf("Could not create nonlocalhost cert: %s", err)
	}

	writeCertificate("ca.cert.pem", caCert)
	writeCertificate("localhost.cert.pem", localhostCert)
	writeCertificate("bad.cert.pem", badCert)
	writePrivateKey("localhost.key.pem", localhostKey)
	writePrivateKey("bad.key.pem", badKey)
}
