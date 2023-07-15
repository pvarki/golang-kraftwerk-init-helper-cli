package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/buger/jsonparser"
	"github.com/k0kubun/pp/v3"
	"github.com/romnn/flags4urfavecli/flags"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// Rev is set on build time to the git HEAD
var Rev = ""

// Version is incremented using bump2version
const Version = "0.1.1"

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
			&cli.IntFlag{
				Name:  "keybits",
				Usage: "How many bits to private key",
				Value: 4096,
			},
			&cli.BoolFlag{
				Name:  "insecure",
				Usage: "Do not verify RASENMAEHER server certificate",
				Value: false,
			},
		},
		Action: func(ctx *cli.Context) error {
			if level, err := log.ParseLevel(ctx.String("log")); err == nil {
				log.SetLevel(level)
			}
			if ctx.Args().Len() < 1 {
				log.Fatal("No manifest path given")
				cli.ShowAppHelpAndExit(ctx, 1)
			}

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
			_ = rmJWT // FIXME: remove when we actually use this value

			certpool, err := readCAs(ctx.String("capath"))
			if err != nil {
				log.Fatal(err)
				return cli.Exit("Could not load CAs", 1)
			}
			log.Debug("certpool: ", pp.Sprint(certpool))

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
			csrpath := filepath.Join(datapath, "public", "mtlsclient.csr")
			err = os.WriteFile(csrpath, csrBytes, 644)
			if err != nil {
				log.Fatal(err)
				return cli.Exit("Could not save CSR", 1)
			}
			log.Info("Wrote ", csrpath)

			// TODO: send the CSR to RASENMAEHER and save the returned cert (remember cfssl encoding for the PEMs)

			return nil
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func createCSR(name string, keys *rsa.PrivateKey) ([]byte, error) {
	var csrTemplate = x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: name},
		SignatureAlgorithm: x509.SHA512WithRSA,
		/*
			TODO: How do we add the extensions for clientAuth ?
		*/
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

func readCAs(capath string) (*x509.CertPool, error) {
	certFiles, err := filepath.Glob(filepath.Join(capath, "*.pem"))
	if err != nil {
		return nil, fmt.Errorf("Failed to scan certificate dir \"%s\": %s", capath, err)
	}
	certpool := x509.NewCertPool()

	sort.Strings(certFiles)
	for _, file := range certFiles {
		log.Info("Adding ", file)
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		for {
			block, rest := pem.Decode(raw)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				certpool.AppendCertsFromPEM(block.Bytes)
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

	log.Info("Generating keypair")
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
	err = os.WriteFile(privkeypath, privKeyPEM.Bytes(), 640)
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
	pubkeypath := path.Join(pubdir, "mtsclient.pub")
	err = os.WriteFile(pubkeypath, pubKeyPEM.Bytes(), 644)
	if err != nil {
		return nil, err
	}
	log.Info("Wrote ", pubkeypath)

	return keypair, nil
}
