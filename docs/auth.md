# Authentication recipes

> Zeerak ships **zero built-in auth** by design (VISION.md §11 Q2). The
> daemon binds to `127.0.0.1:17878` and a unix socket; making it reachable
> from outside loopback is the reverse proxy's job — and so is who's
> allowed in. This file is the cookbook.

The pattern is always the same:

```
browser ──TLS──▶  Caddy / nginx / Tailscale Serve  ──HTTP──▶  zeerak-server
                  (auth happens here)                          (trusts the proxy)
```

Pick whichever recipe matches your setup. They are all **opt-in**, none of them
patch Zeerak — they configure the proxy in front of it.

---

## 1. Homelab: basic auth (60-second setup)

Good for: a single user on a trusted LAN / Tailscale who just wants HTTPS +
a password. **Not** good for production.

```caddyfile
zeerak.example.com {
    basic_auth /* {
        admin $2a$14$REPLACE_WITH_OUTPUT_OF_caddy_hash-password
    }
    reverse_proxy 127.0.0.1:17878
}
```

Generate the hash:

```sh
caddy hash-password --plaintext 'your-secret'
```

Move to forward_auth + OIDC the moment more than one human needs access.

---

## 2. OIDC via Authelia (`forward_auth`)

Authelia is a small, single-binary SSO portal that speaks OIDC and exposes a
`/api/verify` endpoint Caddy can call on every request.

```caddyfile
zeerak.example.com {
    forward_auth auth.example.com:9091 {
        uri /api/verify?rd=https://auth.example.com
        copy_headers Remote-User Remote-Groups Remote-Email Remote-Name
    }
    reverse_proxy 127.0.0.1:17878
}
```

Authelia handles the OIDC dance with Google / GitHub / Keycloak / your IdP
upstream; Zeerak only ever sees the loopback request (with the `Remote-*`
headers attached, in case it ever wants to log them).

**Restrict by group** — Authelia config:

```yaml
# /etc/authelia/configuration.yml
access_control:
  rules:
    - domain: zeerak.example.com
      policy: two_factor
      subject:
        - "group:firewall-admins"
```

---

## 3. OIDC via Authentik (`forward_auth`)

Same shape, different verify endpoint:

```caddyfile
zeerak.example.com {
    forward_auth authentik.example.com {
        uri /outpost.goauthentik.io/auth/caddy
        copy_headers X-authentik-username X-authentik-groups X-authentik-email
        trusted_proxies 127.0.0.1/32
    }
    reverse_proxy 127.0.0.1:17878
}
```

Create an **Application + Provider (Proxy)** in Authentik pointing at
`https://zeerak.example.com`. Authentik handles enrollment, MFA, social
login, and the OIDC handshake.

---

## 4. OIDC direct via Keycloak (oauth2-proxy sidecar)

If your IdP is Keycloak (or any OIDC OP) and you don't want a separate SSO
portal, drop oauth2-proxy in front and have Caddy `forward_auth` to it:

```sh
# systemd: oauth2-proxy.service
ExecStart=/usr/bin/oauth2-proxy \
  --provider=keycloak-oidc \
  --oidc-issuer-url=https://kc.example.com/realms/myrealm \
  --client-id=zeerak \
  --client-secret=$OIDC_SECRET \
  --redirect-url=https://zeerak.example.com/oauth2/callback \
  --email-domain=* \
  --cookie-secret=$COOKIE_SECRET \
  --reverse-proxy=true \
  --http-address=127.0.0.1:4180
```

```caddyfile
zeerak.example.com {
    forward_auth 127.0.0.1:4180 {
        uri /oauth2/auth
        copy_headers X-Auth-Request-User X-Auth-Request-Email X-Auth-Request-Groups
    }
    handle /oauth2/* {
        reverse_proxy 127.0.0.1:4180
    }
    reverse_proxy 127.0.0.1:17878
}
```

---

## 5. Tailscale Serve (zero config, zero TLS, zero passwords)

If your team already has Tailscale, this is the single fastest path:

```sh
# On the Zeerak host:
tailscale serve --bg --https=443 http://127.0.0.1:17878
tailscale funnel --bg off   # keep it tailnet-only, NOT public internet
```

Now `https://<host>.<tailnet>.ts.net` resolves to Zeerak, with mutual TLS
provided by Tailscale, and **only members of your tailnet can reach it**.
ACLs in your Tailscale admin panel decide who exactly. No Caddy required.

For a more granular per-service tag, use Tailscale ACLs:

```jsonc
{
  "acls": [
    {
      "action": "accept",
      "src": ["tag:firewall-admin"],
      "dst": ["tag:zeerak:443"],
    },
  ],
}
```

---

## 6. nginx alternative (`auth_request`)

For shops already on nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name zeerak.example.com;

    location = /auth {
        internal;
        proxy_pass https://auth.example.com/api/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
    }

    location / {
        auth_request /auth;
        auth_request_set $user $upstream_http_remote_user;
        proxy_set_header Remote-User $user;

        proxy_pass http://127.0.0.1:17878;
    }
}
```

---

## 7. Defense in depth: pin Zeerak's UI to a tunnel interface

Even with auth in front, you can use Zeerak _on itself_ to firewall the UI
to your VPN / Tailscale interface only. Edit the SSH preset (or a custom
table) to allow 17878 only from `tailscale0` / `wg0`:

```yaml
presets:
  ssh:
    port: 22
    interfaces: [tailscale0, wg0]
    from: [100.64.0.0/10]
tables:
  - family: inet
    name: zeerak-ui
    chains:
      - name: input
        type: filter
        hook: input
        priority: 0
        policy: drop
        rules:
          - expr: iif lo accept
          - expr: iifname { tailscale0, wg0 } tcp dport 17878 accept
```

Now Zeerak is only reachable over the tunnel even if the reverse proxy
config drifts. Belt + braces.

---

## What Zeerak does _not_ do

- It does not validate JWTs.
- It does not store users, sessions, or API tokens.
- It does not redirect to a login page.
- It does not write to `/etc/passwd`, PAM, or LDAP.
- It does not have a `--auth=oidc` flag and never will.

If you find yourself wanting any of the above, that work belongs in your
reverse proxy or SSO portal, not in Zeerak. The whole "boring tech, single
small binary, no DB" story (VISION.md §1) depends on us not owning auth.
