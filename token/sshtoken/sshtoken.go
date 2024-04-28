//
// Copyright (c) SAS Institute Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package sshtoken

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"io"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"

	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/lib/passprompt"
	"github.com/sassoftware/relic/v7/token"
)

const tokenType = "ssh"

func init() {
	token.Openers[tokenType] = Open
}

type sshToken struct {
	config    *config.Config
	tokenConf *config.TokenConfig
	prompt    passprompt.PasswordGetter
}

type sshKey struct {
	keyConf *config.KeyConfig
	signer  crypto.Signer
	cert    []byte
}

func Open(conf *config.Config, tokenName string, prompt passprompt.PasswordGetter) (token.Token, error) {
	tconf, err := conf.GetToken(tokenName)
	if err != nil {
		return nil, err
	}
	return &sshToken{
		config:    conf,
		tokenConf: tconf,
		prompt:    prompt,
	}, nil
}

func (tok *sshToken) Ping(context.Context) error {
	return nil
}

func (tok *sshToken) Close() error {
	return nil
}

func (tok *sshToken) Config() *config.TokenConfig {
	return tok.tokenConf
}

func (tok *sshToken) ListKeys(opts token.ListOptions) error {
	return token.NotImplementedError{Op: "list-keys", Type: tokenType}
}

func (tok *sshToken) GetKey(ctx context.Context, keyName string) (token.Key, error) {
	keyConf, err := tok.config.GetKey(keyName)
	if err != nil {
		return nil, err
	}

	return &sshKey{
		keyConf: keyConf,
		signer:  nil,
	}, nil
}

func (key *sshKey) Public() crypto.PublicKey {
	_, err := getAgent().(agent.ExtendedAgent).Extension("ssh-yubi-setslot@42wim", []byte(key.keyConf.Slot))
	if err != nil {
		panic(err)
	}

	pubKeyBytes, err := getAgent().(agent.ExtendedAgent).Extension("ssh-yubi-publickey@42wim", nil)
	if err != nil {
		panic(err)
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		panic(err)
	}

	return pubKey.(crypto.PublicKey)
}

func getAgent() agent.Agent {
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		panic(err)
	}

	return agent.NewClient(sshAgent)
}

func (key *sshKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	_, err := getAgent().(agent.ExtendedAgent).Extension("ssh-yubi-setslot@42wim", []byte(key.keyConf.Slot))
	if err != nil {
		return nil, err
	}

	return getAgent().(agent.ExtendedAgent).Extension("ssh-yubi-sign@42wim", digest)
}

func (key *sshKey) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return key.signer.Sign(rand.Reader, digest, opts)
}

func (key *sshKey) Config() *config.KeyConfig {
	return key.keyConf
}

func (key *sshKey) Certificate() []byte {
	return key.cert
}

func (key *sshKey) GetID() []byte {
	return nil
}

func (tok *sshToken) Import(keyName string, privKey crypto.PrivateKey) (token.Key, error) {
	return nil, token.NotImplementedError{Op: "import-key", Type: tokenType}
}

func (tok *sshToken) ImportCertificate(cert *x509.Certificate, labelBase string) error {
	return token.NotImplementedError{Op: "import-certificate", Type: tokenType}
}

func (tok *sshToken) Generate(keyName string, keyType token.KeyType, bits uint) (token.Key, error) {
	// TODO - probably useful
	return nil, token.NotImplementedError{Op: "generate-key", Type: tokenType}
}

func (key *sshKey) ImportCertificate(cert *x509.Certificate) error {
	return token.NotImplementedError{Op: "import-certificate", Type: tokenType}
}
