package litellm

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	operationPrefixLitellm = "litellm"
	secretTypeKey          = "litellm_key"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type litellmBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *client
}

func backend() *litellmBackend {
	b := &litellmBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{configStoragePath, rolesStoragePrefix + "*"},
		},
		Paths: framework.PathAppend(
			pathRoles(b),
			[]*framework.Path{
				pathConfig(b),
				pathCredentials(b),
			},
		),
		Secrets: []*framework.Secret{
			b.key(),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}

	return b
}

func (b *litellmBackend) invalidate(ctx context.Context, key string) {
	if key == configStoragePath {
		b.reset()
	}
}

func (b *litellmBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *litellmBackend) getClient(ctx context.Context, s logical.Storage) (*client, error) {
	b.lock.RLock()
	if b.client != nil {
		defer b.lock.RUnlock()
		return b.client, nil
	}
	b.lock.RUnlock()

	b.lock.Lock()
	defer b.lock.Unlock()
	if b.client != nil {
		return b.client, nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	b.client = newClient(config)
	return b.client, nil
}

const backendHelp = `
The LiteLLM secrets engine issues virtual keys on demand. Every key is bound to
a Vault lease and is deleted from LiteLLM when that lease ends, so services stop
sharing the proxy master key and a leaked key stops working as soon as the lease
is revoked. Each key also carries its own expiry inside LiteLLM, which outlasts
the longest lease only by a margin, so a key still dies on its own if a
revocation never arrives.
`
