package litellm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	errBackendNotConfigured = errors.New("litellm backend is not configured")
	errKeyNotFound          = errors.New("virtual key no longer exists")
)

type client struct {
	http      *http.Client
	url       string
	masterKey string
}

func newClient(c *litellmConfig) *client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if c.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &client{
		http:      &http.Client{Timeout: 30 * time.Second, Transport: transport},
		url:       strings.TrimSuffix(c.URL, "/"),
		masterKey: c.MasterKey,
	}
}

type keyRequest struct {
	KeyAlias  string         `json:"key_alias"`
	Models    []string       `json:"models"`
	Duration  string         `json:"duration,omitempty"`
	MaxBudget float64        `json:"max_budget,omitempty"`
	TPMLimit  int            `json:"tpm_limit,omitempty"`
	RPMLimit  int            `json:"rpm_limit,omitempty"`
	TeamID    string         `json:"team_id,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type keyResponse struct {
	Key     string `json:"key"`
	KeyName string `json:"key_name"`
	TokenID string `json:"token_id"`
}

type deleteRequest struct {
	Keys []string `json:"keys"`
}

func (c *client) do(ctx context.Context, method, path string, body any, out any) error {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.url+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.masterKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return errKeyNotFound
	}
	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("litellm returned %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *client) createKey(ctx context.Context, req *keyRequest) (*keyResponse, error) {
	out := new(keyResponse)
	if err := c.do(ctx, http.MethodPost, "/key/generate", req, out); err != nil {
		return nil, err
	}
	if out.Key == "" {
		return nil, errors.New("litellm returned an empty key")
	}
	return out, nil
}

func (c *client) deleteKey(ctx context.Context, key string) error {
	return c.do(ctx, http.MethodPost, "/key/delete", &deleteRequest{Keys: []string{key}}, nil)
}

func (c *client) ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/key/list?page=1&size=1", nil, nil)
}
