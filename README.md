# vault-plugin-secrets-litellm

A Stronghold (Vault) secrets engine that issues LiteLLM virtual keys on demand.

Services stop carrying the proxy master key. Each one reads a short-lived key
from Stronghold instead, and that key is deleted from LiteLLM the moment its
lease ends.

## Why

The master key is the whole proxy: it mints keys, reads spend, and changes
config. Handing it to every service means one leak exposes everything and
rotating it means restarting everything at once. A virtual key per service, tied
to a lease, turns that into a per-service blast radius with automatic cleanup.

## Safety margin

An issued key carries its own expiry inside LiteLLM (48h) that outlasts the
longest lease (24h). If a revocation never arrives — the engine is down, the
network is cut — the key still dies on its own. The lease is the primary
control; the expiry is the backstop.

## Paths

| Path | What it does |
| --- | --- |
| `config` | URL and master key of the proxy. The master key is never read back. |
| `roles/<name>` | Which models an issued key may call, plus budget and rate limits. |
| `creds/<role>` | Issues a key for that role. |

Models and limits come from the role, never from the request, so a policy that
names one role cannot reach another role's models.

## Usage

```bash
vault secrets enable -path=litellm vault-plugin-secrets-litellm

vault write litellm/config \
  url=http://litellm.c6-staging.svc:8000 \
  master_key=<proxy master key>

vault write litellm/roles/agents \
  models=anthropic:claude-opus-5,openai:gpt-5 \
  max_budget=10 \
  ttl=24h \
  max_ttl=24h

vault read litellm/creds/agents
```

## Development

```bash
make test    # unit tests against a fake proxy
make lint    # go vet
make linux   # build the binary Stronghold loads
```

The tests run against an in-process fake of the LiteLLM key API, so they need
neither a proxy nor a Vault server.
