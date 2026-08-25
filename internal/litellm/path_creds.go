package litellm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	keyLifetime    = 48 * time.Hour
	maxKeyLifetime = 24 * time.Hour
)

func (b *litellmBackend) key() *framework.Secret {
	return &framework.Secret{
		Type: secretTypeKey,
		Fields: map[string]*framework.FieldSchema{
			"key": {
				Type:        framework.TypeString,
				Description: "Virtual key to send as the bearer token.",
			},
			"key_alias": {
				Type:        framework.TypeString,
				Description: "Alias LiteLLM knows this key by.",
			},
		},
		Revoke: b.keyRevoke,
		Renew:  b.keyRenew,
	}
}

func pathCredentials(b *litellmBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("role"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixLitellm,
			OperationVerb:   "generate",
			OperationSuffix: "credentials",
		},
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "Role that decides which models the key may call.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathCredentialsRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathCredentialsRead},
		},
		HelpSynopsis:    "Issue a virtual key for one role.",
		HelpDescription: "The models and the limits come from the role, not from this request, so a policy that names one role cannot reach another role's models.",
	}
}

func (b *litellmBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("role").(string)

	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(roleNotFound(name).Error()), nil
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		if errors.Is(err, errBackendNotConfigured) {
			return logical.ErrorResponse(errMissingConfig.Error()), nil
		}
		return nil, err
	}

	alias := fmt.Sprintf("vault-%s-%d", name, time.Now().UnixNano())

	issued, err := c.createKey(ctx, &keyRequest{
		KeyAlias:  alias,
		Models:    role.Models,
		Duration:  durationForLiteLLM(keyLifetime),
		MaxBudget: role.MaxBudget,
		TPMLimit:  role.TPMLimit,
		RPMLimit:  role.RPMLimit,
		TeamID:    role.TeamID,
		Metadata: map[string]any{
			"issued_by": "vault",
			"role":      name,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("could not create the virtual key: %w", err)
	}

	resp := b.Secret(secretTypeKey).Response(
		map[string]any{
			"key":       issued.Key,
			"key_alias": alias,
		},
		map[string]any{
			"key":       issued.Key,
			"key_alias": alias,
		},
	)

	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL
	if resp.Secret.MaxTTL == 0 || resp.Secret.MaxTTL > maxKeyLifetime {
		resp.Secret.MaxTTL = maxKeyLifetime
	}

	return resp, nil
}

func (b *litellmBackend) keyRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	raw, ok := req.Secret.InternalData["key"]
	if !ok {
		return nil, errors.New("lease is missing the virtual key")
	}

	key, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected key type %T", raw)
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if err := c.deleteKey(ctx, key); err != nil && !errors.Is(err, errKeyNotFound) {
		return nil, fmt.Errorf("could not delete the virtual key: %w", err)
	}

	return nil, nil
}

func (b *litellmBackend) keyRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = req.Secret.Increment
	return resp, nil
}

func durationForLiteLLM(d time.Duration) string {
	return fmt.Sprintf("%ds", int64(d.Seconds()))
}
