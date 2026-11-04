# Vault Plugin: LiteLLM Secrets Backend

A [HashiCorp Vault](https://www.vaultproject.io) secrets engine that issues
[LiteLLM](https://www.litellm.ai) virtual keys on demand and deletes them from
the proxy when their lease ends.

A LiteLLM deployment usually starts with every service holding the proxy master
key, because that is the credential the proxy hands you first. The master key is
not a caller's credential: it mints and deletes keys, reads everyone's spend and
changes the proxy's own configuration. One leak exposes all of it, and rotating
it means restarting every service at once, since nothing else can be swapped
independently.

A virtual key per service turns that into a per-service blast radius, and
binding the key to a Vault lease makes the lease its real lifetime: revoke the
lease and the key stops working within seconds. LiteLLM's own expiry stays as a
backstop, so a key that Vault somehow loses track of still disappears on its
own.

## Quick Links

- [Vault Website](https://www.vaultproject.io)
- [LiteLLM virtual keys](https://docs.litellm.ai/docs/proxy/virtual_keys)
- [Vault plugin system](https://developer.hashicorp.com/vault/docs/plugins)

## Getting Started

This is a [Vault secrets plugin](https://developer.hashicorp.com/vault/docs/secrets)
and is meant to work with Vault. Familiarity with
[plugin registration](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture)
is assumed.

### Build

```sh
make linux
```

The result is a static binary with no runtime dependencies. Put it in the
directory named by `plugin_directory` in the Vault server configuration.

### Register and enable

```sh
SHA=$(sha256sum vault-plugin-secrets-litellm-linux-amd64 | cut -d' ' -f1)

vault plugin register \
  -sha256="$SHA" \
  -command=vault-plugin-secrets-litellm \
  -version=v0.1.0 \
  secret vault-plugin-secrets-litellm

vault secrets enable \
  -path=litellm \
  -plugin-version=v0.1.0 \
  vault-plugin-secrets-litellm
```

## Usage

### Configure the connection

The engine needs a credential that LiteLLM allows to create and delete virtual
keys. The proxy master key is one, and is what the examples assume; a key
carrying the `proxy_admin` role is the other, and is the smaller grant.

Whichever you choose, it is the engine's root credential: give it no budget and
no expiry of its own. Its lifetime is a rotation question rather than an expiry
one, and a root credential that lapses on a day nobody chose takes every issued
key with it.

```sh
vault write litellm/config \
  url=http://litellm.example.svc:8000 \
  master_key=...
```

Writing the configuration calls the proxy and refuses the credential if the
proxy rejects it, so a typo fails immediately rather than at the first issued
key. Reading the configuration never returns the master key.

| Field | Required | Description |
| --- | --- | --- |
| `url` | yes | Base URL of the LiteLLM proxy |
| `master_key` | yes | Credential allowed to mint and delete virtual keys |
| `insecure_tls` | no | Skip verification of the proxy certificate |

### Define a role

A role decides which models an issued key may call and what it may spend. The
models are part of the role rather than of the request, which is what lets a
Vault policy confine a caller to one set of models: grant `litellm/creds/agents`
and the caller cannot reach any other model, because there is nowhere in the
request to name one.

```sh
vault write litellm/roles/agents \
  models=anthropic:claude-opus-5,openai:gpt-5 \
  max_budget=10 \
  rpm_limit=600 \
  ttl=24h \
  max_ttl=24h
```

| Field | Required | Description |
| --- | --- | --- |
| `models` | no | Models the issued keys may call; empty means every model the proxy serves |
| `max_budget` | no | Spend ceiling for one issued key, in dollars |
| `tpm_limit` | no | Tokens per minute allowed for one issued key |
| `rpm_limit` | no | Requests per minute allowed for one issued key |
| `team_id` | no | LiteLLM team the issued keys belong to |
| `ttl` | no | Lifetime of an issued key |
| `max_ttl` | no | Longest an issued key may be renewed for |

An empty `models` is worth a moment's thought: it issues keys that can call
everything the proxy serves, which is convenient and is also how a role stops
confining anything. Name the models unless you mean it.

`max_ttl` cannot exceed the lifetime of the key itself. A role asking for more
is not refused; it is capped, because the cap is a property of the engine rather
than a mistake in the role.

### Issue a credential

```sh
vault read litellm/creds/agents
```

```
Key                Value
---                -----
lease_id           litellm/creds/agents/9kPmT...
lease_duration     24h
lease_renewable    true
key                sk-...
key_alias          vault-agents-1755612345678901234
```

`key` is the bearer token to send as `Authorization: Bearer sk-...`. When the
lease expires or is revoked, the key is deleted from the proxy.

```sh
vault lease revoke litellm/creds/agents/9kPmT...
```

### The expiry behind the lease

Every issued key carries an expiry inside LiteLLM that outlasts the longest
lease. The lease is the control you use; the expiry is what happens when that
control cannot be exercised — the engine is down, the network between Vault and
the proxy is cut, a revocation is lost. Without it a key whose lease vanished
would work forever.

The two are set together in the engine rather than per role, so the margin
cannot be configured into a state where a key dies while something still holds a
valid lease on it. A test asserts the ordering, because the failure it prevents
is silent: keys that stop working mid-lease look like proxy flakiness.

### Restricting a caller to one role

```hcl
path "litellm/creds/agents" {
  capabilities = ["read"]
}
```

That policy grants exactly the models its role names, with exactly the budget
and rate limits the role carries. Nothing in the request can widen it.

## Developing

```sh
make test
```

The tests run against a stub of the LiteLLM key API, so neither a proxy nor a
Vault server is needed to work on the plugin. They cover the parts worth
protecting: that an issued key is scoped to the models its role names, that
revoking a lease deletes the key, that a lease can never be renewed past the
point where the key stops existing, and that the master key is never handed back
out by a read of the configuration.

```sh
make build   # host binary
make linux   # linux/amd64 binary for a Vault server
make lint
```

If Vault is interrupted between creating a key in the proxy and recording the
lease, that key is left behind with nothing pointing at it. What bounds the
damage is the expiry the engine sets on every key it creates, after which the
proxy stops honouring it; the alias it was issued under names the role and the
moment, so a leftover can be recognised from the proxy side.

## Releases

A release carries the `linux/amd64` binary and its `SHA256SUMS`, because that is
what a Vault server needs to fetch and verify. Versions and release notes come
from the commit messages, and the build is attached in the same run, using only
the token GitHub gives the workflow.

## Authorship

Written with [Claude](https://claude.ai). The test suite covers what the plugin
promises, so its behaviour can be checked rather than taken on trust.

## License

Apache License 2.0, see [LICENSE](LICENSE).
