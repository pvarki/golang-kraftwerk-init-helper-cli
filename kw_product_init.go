package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/buger/jsonparser"
	"github.com/go-resty/resty/v2"
	"github.com/k0kubun/pp/v3"
	"github.com/romnn/flags4urfavecli/flags"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// Rev is set on build time to the git HEAD
var Rev = ""

// Version is incremented using bump2version
const Version = "0.1.1"

func commonManifestCheck(cCtx *cli.Context) error {
	log.Debug("cCtx.Args(): ", pp.Sprint(cCtx.Args()))
	if cCtx.Args().Len() < 1 {
		log.Fatal("No manifest path given")
		cli.ShowAppHelpAndExit(cCtx, 1)
	}
	return nil
}

func main() {
	app := &cli.App{
		Version:   Version,
		Usage:     "Create client certs, CSRs etc and get them signed by RASENMAEHER using the info from KRAFTWERK provided manifest file",
		Name:      "kw_product_init",
		ArgsUsage: "/path/to/manifest.json",
		Flags: []cli.Flag{
			&flags.LogLevelFlag,
			&cli.StringFlag{
				Name:  "capath",
				Usage: "Path to CA certificates (directory)",
				Value: "/ca_public",
			},
			&cli.StringFlag{
				Name:  "datapath",
				Usage: "Base path for saving things",
				Value: "/data/persistent",
			},
			&cli.BoolFlag{
				Name:  "insecure",
				Usage: "Do not verify RASENMAEHER server certificate",
				Value: false,
			},
		},
		Before: func(cCtx *cli.Context) error {
			if level, err := log.ParseLevel(cCtx.String("log")); err == nil {
				log.SetLevel(level)
			}
			return nil
		},
		Commands: []*cli.Command{
			&cli.Command{
				Name:   "ping",
				Usage:  "Ping RASENMAEHER healthcheck endpoint",
				Before: commonManifestCheck,
				Action: pingAction,
			},
			&cli.Command{
				Name:   "renew",
				Usage:  "Renew the cert",
				Before: commonManifestCheck,
				Action: renewAction,
			},
			&cli.Command{
				Name:   "init",
				Usage:  "Create key, CSR and get a signed cert",
				Before: commonManifestCheck,
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "keybits",
						Usage: "How many bits to private key",
						Value: 4096,
					},
				},
				Action: initAction,
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func initAction(ctx *cli.Context) error {
	jsondata, err := os.ReadFile(ctx.Args().Get(0))
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Cannot open manifest file", 1)
	}
	dnsName, err := jsonparser.GetString(jsondata, "product", "dns")
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not resolve product DNS name", 1)
	}
	log.Info("Product DNS name ", dnsName)

	rmBase, err := jsonparser.GetString(jsondata, "rasenmaeher", "base_uri")
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not resolve RASENMAEHER address", 1)
	}
	log.Info("Using RASENMAEHER at ", rmBase)

	rmJWT, err := jsonparser.GetString(jsondata, "rasenmaeher", "csr_jwt")
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not resolve RASENMAEHER JWT", 1)
	}

	certpool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not load system CAs", 1)
	}
	certpool, err = readCAs(ctx.String("capath"), certpool)
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not load CAs", 1)
	}
	//log.Debug("certpool: ", pp.Sprint(certpool))

	datapath := ctx.String("datapath")
	keypair, err := createKeyPair(datapath, ctx.Int("keybits"))
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not create keypair", 1)
	}
	//log.Debug("keypair: ", pp.Sprint(keypair))

	csrBytes, err := createCSR(dnsName, keypair)
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not create CSR", 1)
	}
	err = savePublic(csrBytes, "mtlsclient.csr", datapath)
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not save CSR", 1)
	}

	client := resty.New()
	client.SetTLSClientConfig(&tls.Config{
		RootCAs: certpool,
	})
	client.SetAuthScheme("Bearer")
	client.SetAuthToken(rmJWT)

	// FIXME: Put rmBase into the client
	certContent, err := getSignature(csrBytes, datapath, rmBase, client)
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not get CSR signed", 1)
	}
	_ = certContent

	return nil
}

func renewAction(ctx *cli.Context) error {
	log.Debug("Debug test")
	log.Info("Info test")
	msg := "Not implemented"
	log.Fatal(msg)
	return cli.Exit(msg, 1)
}

func pingAction(ctx *cli.Context) error {
	certpool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not load system CAs", 1)
	}
	certpool, err = readCAs(ctx.String("capath"), certpool)
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not load CAs", 1)
	}
	//log.Debug("certpool: ", pp.Sprint(certpool))

	jsondata, err := os.ReadFile(ctx.Args().Get(0))
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Cannot open manifest file", 1)
	}

	rmBase, err := jsonparser.GetString(jsondata, "rasenmaeher", "base_uri")
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not resolve RASENMAEHER address", 1)
	}
	log.Info("Using RASENMAEHER at ", rmBase)

	client := resty.New()
	client.SetTLSClientConfig(&tls.Config{
		RootCAs: certpool,
	})
	url := fmt.Sprintf("%sapi/v1/healthcheck", rmBase)
	log.WithFields(log.Fields{"url": url}).Debug("GETting")
	resp, err := client.R().SetResult(map[string]interface{}{}).Get(url)
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not ping RASENMAEHER", 1)
	}
	if resp.StatusCode() != 200 {
		msg := fmt.Sprintf("Status code %d!=200", resp.StatusCode())
		log.Fatal(msg)
		return cli.Exit("Could not ping RASENMAEHER", 1)
	}
	log.Debug("resp.Body(): ", pp.Sprint(string(resp.Body()[:])))
	log.Debug("resp.Result(): ", pp.Sprint(resp.Result()))
	log.Info("Ping OK")
	return nil
}

func savePublic(content []byte, name string, datapath string) error {
	filepath := filepath.Join(datapath, "public", name)
	err := os.WriteFile(filepath, content, 0644)
	if err != nil {
		return err
	}
	log.Info("Wrote ", filepath)
	return nil
}

func getSignature(csrBytes []byte, datapath string, rmBase string, client *resty.Client) ([]byte, error) {
	url := fmt.Sprintf("%sapi/v1/product/sign_csr", rmBase)
	payload := map[string]interface{}{"csr": string(csrBytes[:])}
	log.WithFields(log.Fields{"payload": payload, "url": url}).Debug("POSTing CSR")
	resp, err := client.R().
		SetResult(map[string]interface{}{}).
		SetBody(payload).
		Post(url)
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("RASENMAEHER replied with error")
	}
	log.Debug("resp.Result(): ", pp.Sprint(resp.Result()))

	certContent, _, _, err := jsonparser.Get(resp.Body(), "certificate")
	if err != nil {
		return nil, err
	}

	err = savePublic(certContent, "mtlsclient.pem", datapath)
	if err != nil {
		return nil, err
	}

	return certContent, nil

}

// references:
//
// https://github.com/tigera/key-cert-provisioner/blob/master/pkg/tls/tls.go#L40
// https://gist.github.com/evantill/ebeb9535458c108e35207e0dbf6fe351#file-main_critical_extendedkeyusage_timestamping-go-L43
// https://github.com/golang/go/issues/13739
func createCSR(name string, keys *rsa.PrivateKey) ([]byte, error) {
	var oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	var oidExtKeyUsageClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	var oidExtKeyUsageServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}

	var certExtentions []pkix.Extension

	basicConstraintsExt := pkix.Extension{}
	basicConstraintsExt.Id = asn1.ObjectIdentifier{2, 5, 29, 19}
	basicConstraintsExt.Critical = true
	val, err := asn1.Marshal(basicConstraints{false, -1})
	if err != nil {
		return nil, err
	}
	basicConstraintsExt.Value = val
	certExtentions = append(certExtentions, basicConstraintsExt)

	extClientAuth := pkix.Extension{}
	extClientAuth.Id = oidExtensionExtendedKeyUsage
	extClientAuth.Critical = true
	val, err = asn1.Marshal([]asn1.ObjectIdentifier{oidExtKeyUsageClientAuth, oidExtKeyUsageServerAuth})
	if err != nil {
		return nil, err
	}
	extClientAuth.Value = val
	certExtentions = append(certExtentions, extClientAuth)

	usageVal, err := marshalKeyUsage(x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment)
	if err != nil {
		return nil, err
	}
	certExtentions = append(certExtentions, usageVal)

	log.Debug("certExtentions: ", pp.Sprint(certExtentions))

	var csrTemplate = x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: name},
		SignatureAlgorithm: x509.SHA512WithRSA,
		ExtraExtensions:    certExtentions,
	}
	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, keys)
	if err != nil {
		return nil, err
	}
	csr := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrCertificate,
	})
	return csr, nil
}

func readCAs(capath string, certpool *x509.CertPool) (*x509.CertPool, error) {
	certFiles, err := filepath.Glob(filepath.Join(capath, "*.pem"))
	if err != nil {
		return nil, fmt.Errorf("Failed to scan certificate dir \"%s\": %s", capath, err)
	}

	sort.Strings(certFiles)
	for _, file := range certFiles {
		log.WithFields(log.Fields{"file": file}).Debug("Adding cert")
		raw, err := os.ReadFile(file)
		if err != nil {
			log.WithFields(log.Fields{"file": file}).Error("Could not open file")
			return nil, err
		}
		for {
			block, rest := pem.Decode(raw)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				certs, err := x509.ParseCertificates(block.Bytes)
				if err != nil {
					log.WithFields(log.Fields{"file": file}).Error("Could parse certs from")
					continue
				}
				for _, cert := range certs {
					certpool.AddCert(cert)
				}
			}
			raw = rest
		}
	}

	return certpool, nil
}

func makeDirectoryIfNotExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.Mkdir(path, os.ModeDir|0755)
	}
	return nil
}

func createKeyPair(datapath string, keybits int) (*rsa.PrivateKey, error) {
	privdir := path.Join(datapath, "private")
	err := makeDirectoryIfNotExists(privdir)
	if err != nil {
		return nil, err
	}
	pubdir := path.Join(datapath, "public")
	err = makeDirectoryIfNotExists(pubdir)
	if err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{"keybits": keybits}).Info("Generating keypair")
	keypair, err := rsa.GenerateKey(rand.Reader, keybits)
	if err != nil {
		return nil, err
	}

	privKeyPEM := new(bytes.Buffer)
	err = pem.Encode(privKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keypair),
	})
	if err != nil {
		return nil, err
	}
	privkeypath := path.Join(privdir, "mtsclient.key")
	err = os.WriteFile(privkeypath, privKeyPEM.Bytes(), 0640)
	if err != nil {
		return nil, err
	}
	log.Info("Wrote ", privkeypath)

	pubKeyPEM := new(bytes.Buffer)
	err = pem.Encode(pubKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&keypair.PublicKey),
	})
	if err != nil {
		return nil, err
	}

	err = savePublic(pubKeyPEM.Bytes(), "mtlsclient.pub", datapath)
	if err != nil {
		return nil, err
	}

	return keypair, nil
}

// basicConstraints is a struct needed for creating a template.
type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// marshalKeyUsage has been copied from the golang package crypto/x509/x509.go in order to marshal keyUsage.
func marshalKeyUsage(ku x509.KeyUsage) (pkix.Extension, error) {
	ext := pkix.Extension{Id: []int{2, 5, 29, 15}, Critical: true}

	var a [2]byte
	a[0] = reverseBitsInAByte(byte(ku))
	a[1] = reverseBitsInAByte(byte(ku >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	var err error
	ext.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	if err != nil {
		return ext, err
	}
	return ext, nil
}

// reverseBitsInAByte has been copied from the golang package crypto/x509/x509.go in order to marshal keyUsage.
func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// asn1BitLength has been copied from the golang package crypto/x509/x509.go in order to marshal keyUsage.
// asn1BitLength returns the bit-length of bitString by considering the most-significant bit in a byte to be the "first"
// bit. This convention matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}
