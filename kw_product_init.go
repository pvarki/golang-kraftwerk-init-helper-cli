package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

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
const Version = "1.4.0+260912"

func fileExist(pth string) bool {
	if _, err := os.Stat(pth); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	} else {
		// Schrodinger: file may or may not exist. See err for details.
		log.Errorf("Can't verify %s: %s", pth, err)
		return false
	}
}

func commonManifestCheck(cCtx *cli.Context) error {
	log.Debug("cCtx.Args(): ", pp.Sprint(cCtx.Args()))
	if cCtx.Args().Len() < 1 {
		log.Fatal("No manifest path given")
		cli.ShowAppHelpAndExit(cCtx, 1)
	}
	if !fileExist(cCtx.Args().Get(0)) {
		log.Fatal("Manifest does not exist")
		cli.ShowAppHelpAndExit(cCtx, 1)
	}
	return nil
}

func main() {
	err := newApp().Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func newApp() *cli.App {
	return &cli.App{
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
				Name:   "ready",
				Usage:  "Report 'ready to serve' to RASENMAEHER",
				Before: commonManifestCheck,
				Action: readyAction,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "productname",
						Usage:    "Product name to report",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "apiurl",
						Usage:    "Product API URL to report",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "userurl",
						Usage:    "Product user URL to report",
						Required: true,
					},
				},
			},
			&cli.Command{
				Name:   "init",
				Usage:  "Create key, CSR and get a signed cert",
				Before: commonManifestCheck,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "keytype",
						Usage: "Private key algorithm: EC or RSA",
						Value: "EC",
					},
					&cli.IntFlag{
						Name:  "keybits",
						Usage: "Private key size (default: EC 256, RSA 4096); EC supports 256, 384 or 521",
					},
				},
				Action: initAction,
			},
		},
	}
}

func readyAction(ctx *cli.Context) error {
	jsondata, err := os.ReadFile(ctx.Args().Get(0))
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Cannot open manifest file", 1)
	}
	datapath := ctx.String("datapath")
	certpath := filepath.Join(datapath, "public", "mtlsclient.pem")
	keypath := filepath.Join(datapath, "private", "mtlsclient.key")
	if !fileExist(certpath) || !fileExist(keypath) {
		msg := "mTLS client cert/key not found"
		log.Fatal(msg)
		return cli.Exit(msg, 1)
	}
	clientKP, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not load mTLS cert/key", 1)
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
	rmBase, err := jsonparser.GetString(jsondata, "rasenmaeher", "mtls", "base_uri")
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not resolve RASENMAEHER address", 1)
	}
	log.Info("Using RASENMAEHER at ", rmBase)

	client := resty.New()
	client.SetTLSClientConfig(&tls.Config{
		RootCAs: certpool,
	})
	client.SetCertificates(clientKP)

	url := fmt.Sprintf("%sapi/v1/product/ready", rmBase)
	payload := map[string]interface{}{
		"product": ctx.String("productname"),
		"apiurl":  ctx.String("apiurl"),
		"url":     ctx.String("userurl"),
	}

	log.WithFields(log.Fields{"payload": payload, "url": url}).Debug("POSTing ready")
	resp, err := client.R().
		SetResult(map[string]interface{}{}).
		SetBody(payload).
		Post(url)
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Error contacting RASENMAEHER", 1)
	}
	if !resp.IsSuccess() {
		log.Debug("resp.Status: ", pp.Sprint(resp.Status()))
		log.Debug("resp.Body: ", pp.Sprint(string(resp.Body())))
		msg := "RASENMAEHER replied with error"
		log.Fatal(msg)
		return cli.Exit(msg, 1)
	}
	log.Debug("resp.Result(): ", pp.Sprint(resp.Result()))

	return nil
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

	rmBase, err := jsonparser.GetString(jsondata, "rasenmaeher", "init", "base_uri")
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not resolve RASENMAEHER address", 1)
	}
	log.Info("Using RASENMAEHER at ", rmBase)

	rmJWT, err := jsonparser.GetString(jsondata, "rasenmaeher", "init", "csr_jwt")
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
	keypair, err := createKeyPair(datapath, ctx.String("keytype"), ctx.Int("keybits"))
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
	jsondata, err := os.ReadFile(ctx.Args().Get(0))
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Cannot open manifest file", 1)
	}
	rmBase, err := jsonparser.GetString(jsondata, "rasenmaeher", "mtls", "base_uri")
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not resolve RASENMAEHER address", 1)
	}
	log.Info("Using RASENMAEHER at ", rmBase)

	datapath := ctx.String("datapath")
	certpath := filepath.Join(datapath, "public", "mtlsclient.pem")
	keypath := filepath.Join(datapath, "private", "mtlsclient.key")
	if !fileExist(certpath) || !fileExist(keypath) {
		msg := "mTLS client cert/key not found"
		log.Fatal(msg)
		return cli.Exit(msg, 1)
	}
	clientKP, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not load mTLS cert/key", 1)
	}
	// Refresh the CSR with the same key, adding a DNS SAN for identities created
	// by older helpers. Renewal must preserve the CN authenticated by mTLS.
	leaf, err := x509.ParseCertificate(clientKP.Certificate[0])
	if err != nil {
		return err
	}
	signer, ok := clientKP.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("mTLS private key cannot sign a CSR")
	}
	csrBytes, err := createCSR(leaf.Subject.CommonName, signer)
	if err != nil {
		return err
	}
	if err := savePublic(csrBytes, "mtlsclient.csr", datapath); err != nil {
		return err
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

	client := resty.New()
	client.SetTLSClientConfig(&tls.Config{
		RootCAs: certpool,
	})
	client.SetCertificates(clientKP)

	// FIXME: Put rmBase into the client
	certContent, err := renewCert(datapath, rmBase, client)
	if err != nil {
		log.Fatal(err)
		return cli.Exit("Could not get CSR signed", 1)
	}
	_ = certContent

	return nil
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

	rmBase, err := jsonparser.GetString(jsondata, "rasenmaeher", "init", "base_uri")
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
	basepath := filepath.Join(datapath, "public")
	tgtpath := filepath.Join(basepath, name)
	if !strings.HasPrefix(filepath.Clean(tgtpath), filepath.Clean(basepath)+string(os.PathSeparator)) {
		return fmt.Errorf("invalid file name %q: path traversal detected", name)
	}
	err := os.WriteFile(tgtpath, content, 0644) // #nosec G703 -- path traversal guarded by HasPrefix check above
	if err != nil {
		return err
	}
	log.Info("Wrote ", tgtpath)
	return nil
}

// FIXME: merge with renewCert
func getSignature(csrBytes []byte, datapath string, rmBase string, client *resty.Client) (string, error) {
	url := fmt.Sprintf("%sapi/v1/product/sign_csr", rmBase)
	payload := map[string]interface{}{"csr": string(csrBytes[:])}
	log.WithFields(log.Fields{"payload": payload, "url": url}).Debug("POSTing CSR")
	resp, err := client.R().
		SetResult(map[string]interface{}{}).
		SetBody(payload).
		Post(url)
	if err != nil {
		return "", err
	}
	if !resp.IsSuccess() {
		log.Errorf("Code: %d body: %s", resp.StatusCode(), resp.Body())
		return "", fmt.Errorf("RASENMAEHER replied with error")
	}
	log.Debug("resp.Result(): ", pp.Sprint(resp.Result()))

	certContent, err := jsonparser.GetString(resp.Body(), "certificate")
	if err != nil {
		return "", err
	}
	certContent = strings.ReplaceAll(certContent, "\\n", "\n")

	err = savePublic([]byte(certContent), "mtlsclient.pem", datapath)
	if err != nil {
		return "", err
	}

	return certContent, nil

}

// FIXME: merge with getSignature
func renewCert(datapath string, rmBase string, client *resty.Client) (string, error) {
	url := fmt.Sprintf("%sapi/v1/product/renew_csr", rmBase)
	csrpath := filepath.Join(datapath, "public", "mtlsclient.csr")
	csrBytes, err := os.ReadFile(csrpath)
	if err != nil {
		return "", err
	}

	payload := map[string]interface{}{"csr": string(csrBytes[:])}
	log.WithFields(log.Fields{"payload": payload, "url": url}).Debug("POSTing CSR")
	resp, err := client.R().
		SetResult(map[string]interface{}{}).
		SetBody(payload).
		Post(url)
	if err != nil {
		return "", err
	}
	if !resp.IsSuccess() {
		return "", fmt.Errorf("RASENMAEHER replied with error")
	}
	log.Debug("resp.Result(): ", pp.Sprint(resp.Result()))

	certContent, err := jsonparser.GetString(resp.Body(), "certificate")
	if err != nil {
		return "", err
	}
	certContent = strings.ReplaceAll(certContent, "\\n", "\n")

	err = savePublic([]byte(certContent), "mtlsclient.pem", datapath)
	if err != nil {
		return "", err
	}

	return certContent, nil

}

// references:
//
// https://github.com/tigera/key-cert-provisioner/blob/master/pkg/tls/tls.go#L40
// https://gist.github.com/evantill/ebeb9535458c108e35207e0dbf6fe351#file-main_critical_extendedkeyusage_timestamping-go-L43
// https://github.com/golang/go/issues/13739
func createCSR(name string, keys crypto.Signer) ([]byte, error) {
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

	usage := x509.KeyUsageDigitalSignature
	if _, ok := keys.(*rsa.PrivateKey); ok {
		usage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
	}
	usageVal, err := marshalKeyUsage(usage)
	if err != nil {
		return nil, err
	}
	certExtentions = append(certExtentions, usageVal)

	log.Debug("certExtentions: ", pp.Sprint(certExtentions))

	var csrTemplate = x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: name},
		DNSNames:        []string{name},
		ExtraExtensions: certExtentions,
	}
	if _, ok := keys.(*rsa.PrivateKey); ok {
		csrTemplate.SignatureAlgorithm = x509.SHA512WithRSA
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
		return nil, fmt.Errorf("failed to scan certificate dir \"%s\": %s", capath, err)
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

func createKeyPair(datapath string, keytype string, keybits int) (crypto.Signer, error) {
	keytype = strings.ToUpper(keytype)
	var curve elliptic.Curve
	switch keytype {
	case "RSA":
		if keybits == 0 {
			keybits = 4096
		}
		if keybits < 2048 {
			return nil, fmt.Errorf("RSA keys require at least 2048 bits")
		}
	case "EC":
		if keybits == 0 {
			keybits = 256
		}
		switch keybits {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("EC keybits must be 256, 384 or 521")
		}
	default:
		return nil, fmt.Errorf("keytype must be EC or RSA")
	}
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

	log.WithFields(log.Fields{"keytype": keytype, "keybits": keybits}).Info("Generating keypair")
	var keypair crypto.Signer
	var privateBlock, publicBlock pem.Block
	if keytype == "RSA" {
		key, err := rsa.GenerateKey(rand.Reader, keybits)
		if err != nil {
			return nil, err
		}
		keypair = key
		privateBlock = pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		publicBlock = pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}
	} else {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		keypair = key
		privateDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return nil, err
		}
		privateBlock = pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}
		publicBlock = pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}
	}

	privKeyPEM := new(bytes.Buffer)
	err = pem.Encode(privKeyPEM, &privateBlock)
	if err != nil {
		return nil, err
	}
	privkeypath := path.Join(privdir, "mtlsclient.key")
	err = os.WriteFile(privkeypath, privKeyPEM.Bytes(), 0640)
	if err != nil {
		return nil, err
	}
	log.Info("Wrote ", privkeypath)

	pubKeyPEM := new(bytes.Buffer)
	err = pem.Encode(pubKeyPEM, &publicBlock)
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
	a[0] = reverseBitsInAByte(byte(uint(ku)))      // #nosec G115 -- intentional bit-slice, copied from stdlib crypto/x509
	a[1] = reverseBitsInAByte(byte(uint(ku) >> 8)) // #nosec G115 -- intentional bit-slice, copied from stdlib crypto/x509

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
