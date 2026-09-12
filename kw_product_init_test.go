package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestInitKeyTypes(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		bits int
		rsa  bool
	}{
		{name: "default EC", bits: 256},
		{name: "EC 384", args: []string{"--keytype", "ec", "--keybits", "384"}, bits: 384},
		{name: "EC 521", args: []string{"--keytype", "EC", "--keybits", "521"}, bits: 521},
		{name: "default RSA", args: []string{"--keytype", "RSA"}, bits: 4096, rsa: true},
		{name: "RSA 2048", args: []string{"--keytype", "rsa", "--keybits", "2048"}, bits: 2048, rsa: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			datapath := t.TempDir()
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodPost || (r.URL.Path != "/api/v1/product/sign_csr" && r.URL.Path != "/api/v1/product/renew_csr") {
					t.Errorf("unexpected signing request: %s %s", r.Method, r.URL.Path)
				}
				if r.URL.Path == "/api/v1/product/sign_csr" && r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("missing bootstrap token")
				}
				if r.URL.Path == "/api/v1/product/renew_csr" && r.Header.Get("Authorization") != "" {
					t.Error("renewal must not reuse the bootstrap token")
				}
				var payload struct{ CSR string }
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				block, _ := pem.Decode([]byte(payload.CSR))
				if block == nil {
					t.Error("missing CSR PEM")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				csr, err := x509.ParseCertificateRequest(block.Bytes)
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if err := csr.CheckSignature(); err != nil {
					t.Error(err)
				}
				if csr.Subject.CommonName != "tak.example.test" || len(csr.DNSNames) != 1 || csr.DNSNames[0] != "tak.example.test" {
					t.Errorf("missing server identity in CSR: %v / %v", csr.Subject, csr.DNSNames)
				}
				for _, ext := range csr.Extensions {
					if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) && !tc.rsa {
						var usage asn1.BitString
						if _, err := asn1.Unmarshal(ext.Value, &usage); err != nil || usage.BitLength != 1 || usage.At(0) != 1 {
							t.Errorf("EC CSR must request only digitalSignature key usage: %v", usage)
						}
					}
				}
				// Issue a certificate to the submitted key, then load it with the saved
				// private key below to verify interoperable PEM output for both algorithms.
				issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				cert := &x509.Certificate{
					SerialNumber: big.NewInt(1), Subject: csr.Subject, DNSNames: csr.DNSNames,
					NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
					KeyUsage:    x509.KeyUsageDigitalSignature,
					ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				}
				der, err := x509.CreateCertificate(rand.Reader, cert, cert, csr.PublicKey, issuerKey)
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]string{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			manifest := filepath.Join(datapath, "manifest.json")
			content, err := json.Marshal(map[string]any{
				"product": map[string]string{"dns": "tak.example.test"},
				"rasenmaeher": map[string]any{
					"init": map[string]string{"base_uri": server.URL + "/", "csr_jwt": "test-token"},
					"mtls": map[string]string{"base_uri": server.URL + "/"},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifest, content, 0600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"kw_product_init", "--capath", datapath, "--datapath", datapath, "init"}, tc.args...)
			if err := newApp().Run(append(args, manifest)); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 1 {
				t.Errorf("expected one CSR request, got %d", requests.Load())
			}
			pair, err := tls.LoadX509KeyPair(filepath.Join(datapath, "public", "mtlsclient.pem"), filepath.Join(datapath, "private", "mtlsclient.key"))
			if err != nil {
				t.Fatal(err)
			}
			switch key := pair.PrivateKey.(type) {
			case *rsa.PrivateKey:
				if !tc.rsa || key.N.BitLen() != tc.bits {
					t.Errorf("unexpected RSA key size %d", key.N.BitLen())
				}
			case *ecdsa.PrivateKey:
				if tc.rsa || key.Curve.Params().BitSize != tc.bits {
					t.Errorf("unexpected EC curve %s", key.Curve.Params().Name)
				}
			default:
				t.Fatalf("unexpected private key type %T", key)
			}
			keyPath := filepath.Join(datapath, "private", "mtlsclient.key")
			keyBefore, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := newApp().Run([]string{"kw_product_init", "--capath", datapath, "--datapath", datapath, "renew", manifest}); err != nil {
				t.Fatal(err)
			}
			keyAfter, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(keyBefore, keyAfter) || requests.Load() != 2 {
				t.Error("renewal must preserve the private key and request one new certificate")
			}
		})
	}
}

func TestInvalidKeyOptions(t *testing.T) {
	for _, tc := range []struct {
		keytype string
		bits    int
	}{{"DSA", 0}, {"EC", 4096}, {"EC", -1}, {"RSA", 1024}} {
		if _, err := createKeyPair(t.TempDir(), tc.keytype, tc.bits); err == nil {
			t.Errorf("accepted invalid key options: %v", tc)
		}
	}
}
