package litellm

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

type litellmConfig struct {
	URL         string `json:"url"`
	MasterKey   string `json:"master_key"`
	InsecureTLS bool   `json:"insecure_tls"`
}

func pathConfig(b *litellmBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixLitellm,
		},
		Fields: map[string]*framework.FieldSchema{
			"url": {
				Type:        framework.TypeString,
				Description: "Base URL of the LiteLLM proxy, without a trailing slash.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:  "LiteLLM URL",
					Value: "http://litellm.example.svc:8000",
				},
			},
			"master_key": {
				Type:        framework.TypeString,
				Description: "Proxy master key, the only credential allowed to mint and delete virtual keys.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Master key",
					Sensitive: true,
					EditType:  "password",
				},
			},
			"insecure_tls": {
				Type:        framework.TypeBool,
				Description: "Skip verification of the LiteLLM certificate.",
				Default:     false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:  "Skip certificate verification",
					Group: "Advanced",
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		ExistenceCheck:  b.pathConfigExistence,
		HelpSynopsis:    "Configure the LiteLLM proxy this engine talks to.",
		HelpDescription: "The master key is never returned once written.",
	}
}

func getConfig(ctx context.Context, s logical.Storage) (*litellmConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := new(litellmConfig)
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

func storeConfig(ctx context.Context, s logical.Storage, config *litellmConfig) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func (b *litellmBackend) pathConfigExistence(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

func (b *litellmBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]any{
			"url":          config.URL,
			"insecure_tls": config.InsecureTLS,
		},
	}, nil
}

func (b *litellmBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = new(litellmConfig)
	}

	if url, ok := data.GetOk("url"); ok {
		config.URL = url.(string)
	}
	if masterKey, ok := data.GetOk("master_key"); ok {
		config.MasterKey = masterKey.(string)
	}
	if insecure, ok := data.GetOk("insecure_tls"); ok {
		config.InsecureTLS = insecure.(bool)
	}

	if config.URL == "" || config.MasterKey == "" {
		return logical.ErrorResponse("url and master_key are both required"), nil
	}

	if err := storeConfig(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	b.reset()

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if err := c.ping(ctx); err != nil {
		return logical.ErrorResponse("litellm rejected this master key: %s", err), nil
	}

	return nil, nil
}

func (b *litellmBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}
	b.reset()
	return nil, nil
}

var errMissingConfig = errors.New("configure the engine at config before issuing keys")
