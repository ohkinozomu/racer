// Based on https://github.com/kubernetes/cloud-provider-aws/blob/a193970a342b690ca5b0d55b3d55b4cd23e1a6a6/cmd/ecr-credential-provider/main.go

/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/spf13/cobra"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

const ecrPublicRegion string = "us-east-1"
const ecrPublicHost string = "public.ecr.aws"

var ecrPrivateHostPattern = regexp.MustCompile(`^(\d{12})\.dkr\.ecr(\-fips)?\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.(amazonaws\.com(\.cn)?|sc2s\.sgov\.gov|c2s\.ic\.gov|cloud\.adc-e\.uk|csp\.hci\.ic\.gov)$`)

// ECR abstracts the calls we make to aws-sdk for testing purposes
type ECR interface {
	GetAuthorizationToken(ctx context.Context, input *ecr.GetAuthorizationTokenInput, opts ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

// ECRPublic abstracts the calls we make to aws-sdk for testing purposes
type ECRPublic interface {
	GetAuthorizationToken(ctx context.Context, input *ecrpublic.GetAuthorizationTokenInput, opts ...func(*ecrpublic.Options)) (*ecrpublic.GetAuthorizationTokenOutput, error)
}

type ecrPlugin struct {
	ecr       ECR
	ecrPublic ECRPublic
	opts      options
}

func defaultECRProvider(ctx context.Context, region string, opts options) (*ecr.Client, error) {
	sessionCredentials, err := getSessionCredentials(opts)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithCredentialsProvider(sessionCredentials))
	if err != nil {
		return nil, err
	}

	return ecr.NewFromConfig(cfg), nil
}

func publicECRProvider(ctx context.Context, opts options) (*ecrpublic.Client, error) {
	sessionCredentials, err := getSessionCredentials(opts)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(ecrPublicRegion), config.WithCredentialsProvider(sessionCredentials))
	if err != nil {
		return nil, err
	}

	return ecrpublic.NewFromConfig(cfg), nil
}

type credsData struct {
	authToken *string
	expiresAt *time.Time
}

func (e *ecrPlugin) getPublicCredsData(ctx context.Context) (*credsData, error) {
	klog.Infof("Getting creds for public registry")
	var err error

	if e.ecrPublic == nil {
		e.ecrPublic, err = publicECRProvider(ctx, e.opts)
	}
	if err != nil {
		return nil, err
	}

	output, err := e.ecrPublic.GetAuthorizationToken(ctx, &ecrpublic.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, err
	}

	if output == nil {
		return nil, errors.New("response output from ECR was nil")
	}

	if output.AuthorizationData == nil {
		return nil, errors.New("authorization data was empty")
	}

	return &credsData{
		authToken: output.AuthorizationData.AuthorizationToken,
		expiresAt: output.AuthorizationData.ExpiresAt,
	}, nil
}

func (e *ecrPlugin) getPrivateCredsData(ctx context.Context, imageHost string, image string) (*credsData, error) {
	klog.Infof("Getting creds for private image %s", image)
	var err error

	if e.ecr == nil {
		region := parseRegionFromECRPrivateHost(imageHost)
		e.ecr, err = defaultECRProvider(ctx, region, e.opts)
		if err != nil {
			return nil, err
		}
	}
	output, err := e.ecr.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, err
	}
	if output == nil {
		return nil, errors.New("response output from ECR was nil")
	}
	if len(output.AuthorizationData) == 0 {
		return nil, errors.New("authorization data was empty")
	}
	return &credsData{
		authToken: output.AuthorizationData[0].AuthorizationToken,
		expiresAt: output.AuthorizationData[0].ExpiresAt,
	}, nil
}

func (e *ecrPlugin) GetCredentials(ctx context.Context, image string, args []string) (*v1.CredentialProviderResponse, error) {
	var creds *credsData
	var err error

	imageHost, err := parseHostFromImageReference(image)
	if err != nil {
		return nil, err
	}

	if imageHost == ecrPublicHost {
		creds, err = e.getPublicCredsData(ctx)
	} else {
		creds, err = e.getPrivateCredsData(ctx, imageHost, image)
	}

	if err != nil {
		return nil, err
	}

	if creds.authToken == nil {
		return nil, errors.New("authorization token in response was nil")
	}

	decodedToken, err := base64.StdEncoding.DecodeString(aws.ToString(creds.authToken))
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(string(decodedToken), ":", 2)
	if len(parts) != 2 {
		return nil, errors.New("error parsing username and password from authorization token")
	}

	cacheDuration := getCacheDuration(creds.expiresAt)

	return &v1.CredentialProviderResponse{
		CacheKeyType:  v1.RegistryPluginCacheKeyType,
		CacheDuration: cacheDuration,
		Auth: map[string]v1.AuthConfig{
			imageHost: {
				Username: parts[0],
				Password: parts[1],
			},
		},
	}, nil

}

// getCacheDuration calculates the credentials cache duration based on the ExpiresAt time from the authorization data
func getCacheDuration(expiresAt *time.Time) *metav1.Duration {
	var cacheDuration *metav1.Duration
	if expiresAt == nil {
		// explicitly set cache duration to 0 if expiresAt was nil so that
		// kubelet does not cache it in-memory
		cacheDuration = &metav1.Duration{Duration: 0}
	} else {
		// halving duration in order to compensate for the time loss between
		// the token creation and passing it all the way to kubelet.
		duration := time.Second * time.Duration((expiresAt.Unix()-time.Now().Unix())/2)
		if duration > 0 {
			cacheDuration = &metav1.Duration{Duration: duration}
		}
	}
	return cacheDuration
}

// parseHostFromImageReference parses the hostname from an image reference
func parseHostFromImageReference(image string) (string, error) {
	// a URL needs a scheme to be parsed correctly
	if !strings.Contains(image, "://") {
		image = "https://" + image
	}
	parsed, err := url.Parse(image)
	if err != nil {
		return "", fmt.Errorf("error parsing image reference %s: %v", image, err)
	}
	return parsed.Hostname(), nil
}

func parseRegionFromECRPrivateHost(host string) string {
	splitHost := ecrPrivateHostPattern.FindStringSubmatch(host)
	if len(splitHost) != 6 {
		return ""
	}
	return splitHost[3]
}

func main() {
	var opts options

	cmd := &cobra.Command{
		Use:     "racer",
		Short:   "RACER: Roles Anywhere Credential for ECR",
		Version: gitVersion,
		Run: func(cmd *cobra.Command, args []string) {
			p := NewCredentialProvider(&ecrPlugin{opts: opts})
			if err := p.Run(context.TODO()); err != nil {
				klog.Errorf("Error running credential provider plugin: %v", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(&opts.bundlePath, "bundle-path", "", "Path to certificate bundle")
	cmd.Flags().StringVar(&opts.certPath, "cert-path", "certs/alice-cert.crt", "Path to certificate")
	cmd.Flags().StringVar(&opts.awsRegion, "aws-region", "us-east-2", "AWS region")
	cmd.Flags().StringVar(&opts.roleARN, "role-arn", "arn:aws:iam::291738886548:role/rolesanywhere1", "Role ARN")
	cmd.Flags().StringVar(&opts.trustAnchorARN, "trust-anchor-arn", "arn:aws:rolesanywhere:us-east-2:291738886548:trust-anchor/a545a1fc-5d86-4032-8f4c-61cdd6ff92da", "Trust Anchor ARN")
	cmd.Flags().StringVar(&opts.profileARN, "profile-arn", "arn:aws:rolesanywhere:us-east-2:291738886548:profile/6f4943fb-13d4-4242-89c4-be367595c380", "Profile ARN")
	cmd.Flags().StringVar(&opts.tpmPath, "tpm-path", "127.0.0.1:2321", "Path to TPM")
	cmd.Flags().IntVar(&opts.persistentHandle, "persistent-handle", 0, "Persistent handle")
	cmd.Flags().StringVar(&opts.tpmPrivateKey, "tpm-private-key", "", "TPM private key")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var gitVersion string
