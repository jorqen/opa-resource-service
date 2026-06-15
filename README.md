# opa-resource-service

An HTTP service that authorizes requests with [Open Policy Agent](https://www.openpolicyagent.org/)
embedded as a Go library. The single endpoint `GET /resource` is protected by a
Keycloak bearer token; the user's realm roles are extracted from the token and
checked against a Rego policy on every request.

## How it works

1. The `Authorization: Bearer <jwt>` header is parsed for Keycloak realm roles
   (`realm_access.roles`).
2. An OPA `input` document is built from the request: `{method, path, roles}`.
3. The prepared query `data.authz.allow` is evaluated against that input.
4. `allow == true` lets the request reach the handler; otherwise it is rejected.

The Rego query is compiled once at startup with `PrepareForEval` and reused for
every request.

> The OPA SDK is imported from `github.com/open-policy-agent/opa/v1/rego` — the
> non-deprecated v1.x path with the same API as the `opa/rego` package named in
> the brief (the older path is flagged as deprecated by `staticcheck`).

### Policy

[`policy/authz.rego`](policy/authz.rego):

- `admin` is allowed any method.
- `reader` is allowed `GET`.
- everything else is denied (`default allow := false`).

## Requirements

- Go 1.25+ (required by the OPA library)
- [`opa`](https://www.openpolicyagent.org/docs/latest/#running-opa) CLI — only to run the policy tests

## Run

```sh
go run ./cmd/server
```

| flag      | default             | description                                   |
|-----------|---------------------|-----------------------------------------------|
| `-addr`   | `:8080`             | HTTP listen address                           |
| `-policy` | `policy/authz.rego` | path to the Rego policy (hot-reloaded on edit) |

## Try it

The tokens below are unsigned, mocked Keycloak JWTs (see
[note on verification](#note-on-jwt-verification)); decode the middle segment to
inspect their claims.

`alice` has the `reader` role — allowed:

```sh
curl -i http://localhost:8080/resource \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMC1yZWFkZXIiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGljZSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJyZWFkZXIiXX19.c2lnbmF0dXJl"
# 200 {"message":"access granted","user":"alice"}
```

`bob` has the `admin` role — allowed:

```sh
curl -i http://localhost:8080/resource \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMC1hZG1pbiIsInByZWZlcnJlZF91c2VybmFtZSI6ImJvYiIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJhZG1pbiJdfX0.c2lnbmF0dXJl"
# 200 {"message":"access granted","user":"bob"}
```

`eve` has only an unknown `guest` role — denied:

```sh
curl -i http://localhost:8080/resource \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMC1ndWVzdCIsInByZWZlcnJlZF91c2VybmFtZSI6ImV2ZSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJndWVzdCJdfX0.c2lnbmF0dXJl"
# 403 {"error":"Forbidden","message":"access denied: insufficient role"}
```

No (or malformed) token — unauthorized:

```sh
curl -i http://localhost:8080/resource
# 401 {"error":"Unauthorized","message":"missing bearer token"}
```

Mint your own token for other roles:

```sh
python3 - <<'PY'
import base64, json
enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
claims = {"preferred_username": "carol", "realm_access": {"roles": ["reader", "admin"]}}
print(enc(b'{"alg":"RS256","typ":"JWT"}') + "." + enc(json.dumps(claims).encode()) + "." + enc(b'signature'))
PY
```

## Tests

```sh
go test ./...        # claim parsing, OPA authorizer, HTTP middleware
opa test policy/ -v  # Rego policy
```

## Layout

```
cmd/server      entrypoint: flags, signal handling, graceful shutdown
internal/auth   Keycloak JWT claim extraction
internal/authz  OPA wrapper: PrepareForEval, evaluation, hot-reload
internal/server HTTP handler, auth middleware, JSON responses
policy          Rego policy and its tests
```

## Bonus features

- **Hot-reload** — the policy file is watched; a valid edit is recompiled and
  swapped in atomically, with no restart and no dropped requests. An invalid
  edit is logged and ignored, keeping the last good policy in effect.
- **Clear denials** — `401` and `403` return a JSON `{"error", "message"}` body
  rather than an empty response.

## Note on JWT verification

`ParseClaims` decodes the token payload but does **not** verify its signature, so
claims can be supplied by a mocked token. In production the token would be
validated against Keycloak's JWKS endpoint before its claims are trusted.
