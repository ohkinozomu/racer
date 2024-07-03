// Based on https://github.com/salrashid123/aws_rolesanywhere_signer/blob/f3fa52dd87e45c689c741683674beca78f38e30e/example/tpm/nopolicy/main.go

package main

import (
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
	rolesanywhere "github.com/salrashid123/aws_rolesanywhere_signer"
	saltpm "github.com/salrashid123/signer/tpm"
)

var tpmDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(tpmDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

type options struct {
	bundlePath       string
	certPath         string
	awsRegion        string
	roleARN          string
	trustAnchorARN   string
	profileARN       string
	tpmPath          string
	persistentHandle int
	tpmPrivateKey    string
}

func getSessionCredentials(opts options) (aws.CredentialsProvider, error) {
	if opts.persistentHandle != 0 && opts.tpmPrivateKey != "" {
		return nil, fmt.Errorf("can't specify both persistentHandle and TPMPrivateKey")
	}
	rwc, err := openTPM(opts.tpmPath)
	if err != nil {
		return nil, fmt.Errorf("can't open TPM  %v", err)
	}
	defer rwc.Close()
	rwr := transport.FromReadWriter(rwc)

	var chain []*x509.Certificate
	if opts.bundlePath != "" {
		var err error
		chain, err = helper.GetCertChain(opts.bundlePath)
		if err != nil {
			return nil, fmt.Errorf("Failed to read certificate bundle: %s\n", err)
		}
	}
	var cert *x509.Certificate
	if opts.certPath != "" {
		var err error
		_, cert, err = helper.ReadCertificateData(opts.certPath)
		if err != nil {
			return nil, fmt.Errorf("error reading certificate %v", err)
		}
	} else if len(chain) > 0 {
		cert = chain[0]
	} else {
		return nil, fmt.Errorf("No certificate path or certificate bundle path provided")
	}

	var handle tpm2.TPMHandle
	if opts.tpmPrivateKey != "" {
		kb, err := os.ReadFile(opts.tpmPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("can't read keyfile  %v", err)
		}
		k, err := keyfile.Decode(kb)
		if err != nil {
			return nil, fmt.Errorf("can't decoding keyfile  %v", err)
		}

		primaryKey, err := tpm2.CreatePrimary{
			PrimaryHandle: k.Parent,
			InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("can't create primary %v", err)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: primaryKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		regenRSAKey, err := tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: primaryKey.ObjectHandle,
				Name:   tpm2.TPM2BName(primaryKey.Name),
				Auth:   tpm2.PasswordAuth([]byte("")),
			},
			InPublic:  k.Pubkey,
			InPrivate: k.Privkey,
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("can't loading key from keyfile  %v", err)
		}
		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: regenRSAKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()
		handle = regenRSAKey.ObjectHandle

	} else {
		handle = tpm2.TPMHandle(opts.persistentHandle)
	}

	pub, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("error executing tpm2.ReadPublic %s", err)
	}

	s, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: rwc,
		NamedHandle: &tpm2.NamedHandle{
			Handle: handle,
			Name:   pub.Name,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error getting signer %v\n", err)
	}

	sessionCredentials, err := rolesanywhere.NewAWSRolesAnywhereSignerCredentials(rolesanywhere.SignerProvider{
		CredentialsOpts: rolesanywhere.CredentialsOpts{
			Region:            opts.awsRegion,
			RoleArn:           opts.roleARN,
			TrustAnchorArnStr: opts.trustAnchorARN,
			ProfileArnStr:     opts.profileARN,
			Certificate:       cert,
			CertificateChain:  chain,
			Debug:             false,
		},
		Signer: &s,
	})
	if err != nil {
		return nil, fmt.Errorf("Could not initialize TPM Credentials %v\n", err)
	}

	return sessionCredentials, nil
}
