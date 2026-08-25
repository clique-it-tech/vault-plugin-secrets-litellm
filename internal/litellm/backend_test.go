package litellm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

type fakeLitellm struct {
	server      *httptest.Server
	created     []keyRequest
	deleted     []string
	authSeen    []string
	nextID      int
	refuseAuth  bool
	emptyKey    bool
	missingKeys map[string]bool
}

func newFakeLitellm(t *testing.T) *fakeLitellm {
	t.Helper()
	f := &fakeLitellm{nextID: 1, missingKeys: map[string]bool{}}

	mux := http.NewServeMux()

	mux.HandleFunc("/key/generate", func(w http.ResponseWriter, r *http.Request) {
		f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
		if f.refuseAuth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req keyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.created = append(f.created, req)
		id := f.nextID
		f.nextID++
		out := keyResponse{KeyName: req.KeyAlias, TokenID: fmt.Sprintf("token-%d", id)}
		if !f.emptyKey {
			out.Key = fmt.Sprintf("sk-issued-%d", id)
		}
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/key/delete", func(w http.ResponseWriter, r *http.Request) {
		var req deleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, k := range req.Keys {
			if f.missingKeys[k] {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			f.deleted = append(f.deleted, k)
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/key/list", func(w http.ResponseWriter, r *http.Request) {
		f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
		if f.refuseAuth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"keys":[]}`))
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func testBackend(t *testing.T) (*litellmBackend, logical.Storage) {
	t.Helper()
	storage := &logical.InmemStorage{}
	b := backend()
	if err := b.Setup(context.Background(), &logical.BackendConfig{
		StorageView: storage,
		Logger:      nil,
		System:      &logical.StaticSystemView{},
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	return b, storage
}

func write(t *testing.T, b *litellmBackend, s logical.Storage, path string, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Data:      data,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return resp
}

func read(t *testing.T, b *litellmBackend, s logical.Storage, path string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp
}

func configure(t *testing.T, b *litellmBackend, s logical.Storage, f *fakeLitellm) {
	t.Helper()
	resp := write(t, b, s, "config", map[string]any{
		"url":        f.server.URL,
		"master_key": "sk-master",
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("configure: %v", resp.Error())
	}
}

func TestIssuedKeyIsScopedToTheRoleAndDeletedWhenTheLeaseEnds(t *testing.T) {
	f := newFakeLitellm(t)
	b, s := testBackend(t)
	configure(t, b, s, f)

	write(t, b, s, "roles/agents", map[string]any{
		"models":     "anthropic:claude-opus-5,openai:gpt-5",
		"max_budget": 5.5,
		"ttl":        "1h",
	})

	resp := read(t, b, s, "creds/agents")
	if resp == nil || resp.IsError() {
		t.Fatalf("issuing failed: %v", resp)
	}

	key, _ := resp.Data["key"].(string)
	if !strings.HasPrefix(key, "sk-issued-") {
		t.Fatalf("expected an issued key, got %q", key)
	}

	if len(f.created) != 1 {
		t.Fatalf("expected one key created, got %d", len(f.created))
	}
	created := f.created[0]
	if got := strings.Join(created.Models, ","); got != "anthropic:claude-opus-5,openai:gpt-5" {
		t.Fatalf("key was not scoped to the role models: %q", got)
	}
	if created.MaxBudget != 5.5 {
		t.Fatalf("budget from the role was not applied: %v", created.MaxBudget)
	}
	if !strings.HasPrefix(created.KeyAlias, "vault-agents-") {
		t.Fatalf("alias should name the role: %q", created.KeyAlias)
	}

	revoke, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/agents",
		Storage:   s,
		Secret:    resp.Secret,
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoke != nil && revoke.IsError() {
		t.Fatalf("revoke returned an error: %v", revoke.Error())
	}
	if len(f.deleted) != 1 || f.deleted[0] != key {
		t.Fatalf("the lease did not delete the key it issued: %v", f.deleted)
	}
}

func TestALeaseCannotOutliveTheKey(t *testing.T) {
	f := newFakeLitellm(t)
	b, s := testBackend(t)
	configure(t, b, s, f)

	write(t, b, s, "roles/wide", map[string]any{"ttl": "1h", "max_ttl": "720h"})

	resp := read(t, b, s, "creds/wide")
	if resp.Secret.MaxTTL > maxKeyLifetime {
		t.Fatalf("lease may outlive the key: max_ttl %s", resp.Secret.MaxTTL)
	}
}

func TestTheKeyOutlivesTheLongestLease(t *testing.T) {
	if keyLifetime <= maxKeyLifetime {
		t.Fatalf("a key must outlast the longest lease, otherwise it dies while still leased")
	}
}

func TestARoleWithoutAMaxIsStillCapped(t *testing.T) {
	f := newFakeLitellm(t)
	b, s := testBackend(t)
	configure(t, b, s, f)

	write(t, b, s, "roles/plain", map[string]any{"ttl": "1h"})

	resp := read(t, b, s, "creds/plain")
	if resp.Secret.MaxTTL != maxKeyLifetime {
		t.Fatalf("expected the default cap, got %s", resp.Secret.MaxTTL)
	}
}

func TestIssuingWithoutARoleIsRefused(t *testing.T) {
	f := newFakeLitellm(t)
	b, s := testBackend(t)
	configure(t, b, s, f)

	resp := read(t, b, s, "creds/nobody")
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected a refusal, got %v", resp)
	}
	if len(f.created) != 0 {
		t.Fatalf("a key was created for a role that does not exist")
	}
}

func TestIssuingWithoutConfigIsRefused(t *testing.T) {
	b, s := testBackend(t)
	write(t, b, s, "roles/agents", map[string]any{"ttl": "1h"})

	resp := read(t, b, s, "creds/agents")
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected a refusal, got %v", resp)
	}
	if !strings.Contains(resp.Error().Error(), "configure the engine") {
		t.Fatalf("the refusal should say what to do: %v", resp.Error())
	}
}

func TestTheMasterKeyIsNeverReturned(t *testing.T) {
	f := newFakeLitellm(t)
	b, s := testBackend(t)
	configure(t, b, s, f)

	resp := read(t, b, s, "config")
	if resp == nil {
		t.Fatal("expected the config to be readable")
	}
	if _, present := resp.Data["master_key"]; present {
		t.Fatal("the master key was handed back out")
	}
	if resp.Data["url"] != f.server.URL {
		t.Fatalf("url should be readable: %v", resp.Data["url"])
	}
}

func TestEveryCallCarriesTheMasterKey(t *testing.T) {
	f := newFakeLitellm(t)
	b, s := testBackend(t)
	configure(t, b, s, f)

	write(t, b, s, "roles/agents", map[string]any{"ttl": "1h"})
	read(t, b, s, "creds/agents")

	if len(f.authSeen) == 0 {
		t.Fatal("no request reached the proxy")
	}
	for _, header := range f.authSeen {
		if header != "Bearer sk-master" {
			t.Fatalf("a request went out without the master key: %q", header)
		}
	}
}

func TestConfigIsRefusedWhenTheProxyRejectsTheMasterKey(t *testing.T) {
	f := newFakeLitellm(t)
	f.refuseAuth = true
	b, s := testBackend(t)

	resp := write(t, b, s, "config", map[string]any{
		"url":        f.server.URL,
		"master_key": "sk-wrong",
	})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the bad master key to be refused, got %v", resp)
	}
}

func TestConfigNeedsBothUrlAndMasterKey(t *testing.T) {
	b, s := testBackend(t)

	resp := write(t, b, s, "config", map[string]any{"url": "http://litellm.example"})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected a refusal when the master key is missing, got %v", resp)
	}
}

func TestAnEmptyKeyFromTheProxyIsAnError(t *testing.T) {
	f := newFakeLitellm(t)
	b, s := testBackend(t)
	configure(t, b, s, f)
	f.emptyKey = true

	write(t, b, s, "roles/agents", map[string]any{"ttl": "1h"})

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/agents",
		Storage:   s,
	})
	if err == nil {
		t.Fatal("an empty key should not be handed to a caller as if it worked")
	}
}

func TestRevokingAKeyTheProxyAlreadyLostSucceeds(t *testing.T) {
	f := newFakeLitellm(t)
	b, s := testBackend(t)
	configure(t, b, s, f)

	write(t, b, s, "roles/agents", map[string]any{"ttl": "1h"})
	resp := read(t, b, s, "creds/agents")

	key := resp.Data["key"].(string)
	f.missingKeys[key] = true

	revoke, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/agents",
		Storage:   s,
		Secret:    resp.Secret,
	})
	if err != nil {
		t.Fatalf("a key already gone from the proxy must not block revocation: %v", err)
	}
	if revoke != nil && revoke.IsError() {
		t.Fatalf("revoke returned an error: %v", revoke.Error())
	}
}

func TestARoleCannotAskForATtlLongerThanItsMax(t *testing.T) {
	f := newFakeLitellm(t)
	b, s := testBackend(t)
	configure(t, b, s, f)

	resp := write(t, b, s, "roles/backwards", map[string]any{"ttl": "10h", "max_ttl": "1h"})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected the contradiction to be refused, got %v", resp)
	}
}

func TestRolesAreListedAndCanBeDeleted(t *testing.T) {
	f := newFakeLitellm(t)
	b, s := testBackend(t)
	configure(t, b, s, f)

	write(t, b, s, "roles/one", map[string]any{"ttl": "1h"})
	write(t, b, s, "roles/two", map[string]any{"ttl": "1h"})

	listed, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	keys := listed.Data["keys"].([]string)
	if len(keys) != 2 {
		t.Fatalf("expected both roles listed, got %v", keys)
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/one",
		Storage:   s,
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if read(t, b, s, "roles/one") != nil {
		t.Fatal("the deleted role is still readable")
	}
}

func TestTwoIssuesNeverShareAnAlias(t *testing.T) {
	f := newFakeLitellm(t)
	b, s := testBackend(t)
	configure(t, b, s, f)

	write(t, b, s, "roles/agents", map[string]any{"ttl": "1h"})
	first := read(t, b, s, "creds/agents")
	second := read(t, b, s, "creds/agents")

	if first.Data["key_alias"] == second.Data["key_alias"] {
		t.Fatal("two keys share an alias, so deleting one would take the other")
	}
	if first.Data["key"] == second.Data["key"] {
		t.Fatal("two issues returned the same key")
	}
}

func TestTheKeyDurationSentToTheProxyIsAWholeNumberOfSeconds(t *testing.T) {
	f := newFakeLitellm(t)
	b, s := testBackend(t)
	configure(t, b, s, f)

	write(t, b, s, "roles/agents", map[string]any{"ttl": "1h"})
	read(t, b, s, "creds/agents")

	got := f.created[0].Duration
	want := fmt.Sprintf("%ds", int64(keyLifetime.Seconds()))
	if got != want {
		t.Fatalf("duration %q is not what the proxy expects (%q)", got, want)
	}
}

func TestChangingTheConfigMakesTheNextCallUseIt(t *testing.T) {
	first := newFakeLitellm(t)
	second := newFakeLitellm(t)
	b, s := testBackend(t)

	configure(t, b, s, first)
	write(t, b, s, "roles/agents", map[string]any{"ttl": "1h"})
	read(t, b, s, "creds/agents")

	configure(t, b, s, second)
	read(t, b, s, "creds/agents")

	if len(second.created) != 1 {
		t.Fatalf("the new proxy was not used after the config changed: %d", len(second.created))
	}
	if len(first.created) != 1 {
		t.Fatalf("the old proxy kept being used: %d", len(first.created))
	}
}

func TestARenewalDoesNotOutrunTheKey(t *testing.T) {
	f := newFakeLitellm(t)
	b, s := testBackend(t)
	configure(t, b, s, f)

	write(t, b, s, "roles/agents", map[string]any{"ttl": "1h", "max_ttl": "24h"})
	resp := read(t, b, s, "creds/agents")

	resp.Secret.Increment = 2 * time.Hour
	renewed, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/agents",
		Storage:   s,
		Secret:    resp.Secret,
	})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed.Secret.TTL != 2*time.Hour {
		t.Fatalf("renewal did not take the increment: %s", renewed.Secret.TTL)
	}
	if renewed.Secret.MaxTTL > maxKeyLifetime {
		t.Fatalf("renewal pushed the lease past the key: %s", renewed.Secret.MaxTTL)
	}
}
