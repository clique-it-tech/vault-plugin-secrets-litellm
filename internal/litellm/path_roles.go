package litellm

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const rolesStoragePrefix = "role/"

type litellmRole struct {
	Models    []string      `json:"models"`
	MaxBudget float64       `json:"max_budget"`
	TPMLimit  int           `json:"tpm_limit"`
	RPMLimit  int           `json:"rpm_limit"`
	TeamID    string        `json:"team_id"`
	TTL       time.Duration `json:"ttl"`
	MaxTTL    time.Duration `json:"max_ttl"`
}

func (r *litellmRole) toResponseData() map[string]any {
	return map[string]any{
		"models":     r.Models,
		"max_budget": r.MaxBudget,
		"tpm_limit":  r.TPMLimit,
		"rpm_limit":  r.RPMLimit,
		"team_id":    r.TeamID,
		"ttl":        int64(r.TTL.Seconds()),
		"max_ttl":    int64(r.MaxTTL.Seconds()),
	}
}

func pathRoles(b *litellmBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixLitellm,
				OperationSuffix: "role",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role.",
					Required:    true,
				},
				"models": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Models the issued keys may call. Empty means every model the proxy serves.",
					DisplayAttrs: &framework.DisplayAttributes{
						Name:  "Models",
						Value: "anthropic:claude-opus-5,openai:gpt-5",
					},
				},
				"max_budget": {
					Type:        framework.TypeFloat,
					Description: "Spend ceiling for one issued key, in dollars. Zero leaves the key uncapped.",
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Budget",
					},
				},
				"tpm_limit": {
					Type:        framework.TypeInt,
					Description: "Tokens per minute allowed for one issued key. Zero leaves it unlimited.",
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Tokens per minute",
					},
				},
				"rpm_limit": {
					Type:        framework.TypeInt,
					Description: "Requests per minute allowed for one issued key. Zero leaves it unlimited.",
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Requests per minute",
					},
				},
				"team_id": {
					Type:        framework.TypeString,
					Description: "LiteLLM team the issued keys belong to.",
					DisplayAttrs: &framework.DisplayAttributes{
						Name:  "Team",
						Group: "Advanced",
					},
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Lifetime of an issued key.",
					DisplayAttrs: &framework.DisplayAttributes{
						Name:     "Lease",
						EditType: "ttl",
					},
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Longest an issued key may be renewed for.",
					DisplayAttrs: &framework.DisplayAttributes{
						Name:     "Longest lease",
						EditType: "ttl",
					},
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRolesRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRolesDelete},
			},
			ExistenceCheck:  b.pathRolesExistence,
			HelpSynopsis:    "Describe what an issued key is allowed to do.",
			HelpDescription: "Models and limits come from the role, so a policy that names one role cannot reach another role's models.",
		},
		{
			Pattern: "roles/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixLitellm,
				OperationSuffix: "roles",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRolesList},
			},
			HelpSynopsis: "List the roles this engine knows.",
		},
	}
}

func roleNotFound(name string) error {
	return fmt.Errorf("no role named %s", name)
}

func getRole(ctx context.Context, s logical.Storage, name string) (*litellmRole, error) {
	entry, err := s.Get(ctx, rolesStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	role := new(litellmRole)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

func (b *litellmBackend) pathRolesExistence(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *litellmBackend) pathRolesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{Data: role.toResponseData()}, nil
}

func (b *litellmBackend) pathRolesWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = new(litellmRole)
	}

	if models, ok := data.GetOk("models"); ok {
		role.Models = models.([]string)
	}
	if budget, ok := data.GetOk("max_budget"); ok {
		role.MaxBudget = budget.(float64)
	}
	if tpm, ok := data.GetOk("tpm_limit"); ok {
		role.TPMLimit = tpm.(int)
	}
	if rpm, ok := data.GetOk("rpm_limit"); ok {
		role.RPMLimit = rpm.(int)
	}
	if team, ok := data.GetOk("team_id"); ok {
		role.TeamID = team.(string)
	}
	if ttl, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(ttl.(int)) * time.Second
	}
	if maxTTL, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTL.(int)) * time.Second
	}

	if role.MaxTTL != 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be longer than max_ttl"), nil
	}

	entry, err := logical.StorageEntryJSON(rolesStoragePrefix+name, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *litellmBackend) pathRolesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, rolesStoragePrefix+data.Get("name").(string)); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *litellmBackend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, rolesStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}
