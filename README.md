# be-edge

The edge's session layer of BrickEnterprise (be-protocol chapter 11, rules P11.1–P11.10). For a browser request with
the session cookie it injects the session's short access token, exchanged from the identity member's standard system
method `be.session.v1.SessionService` and cached per session; it replays the request once when the entry component
answers `TOKEN_STALE`; state-changing requests with the cookie need `BE-Request: 1`; `features` goes to live sessions
only; every edge instance pulls the ended sessions by cursor. It does not verify tokens or decide authorization:
every component does that itself.

- The package at the root is a Traefik middleware plugin (Yaegi): standard library only, gRPC framed by hand.
- Another edge product gets a sidecar wrapping the same handler (not built yet), held to the same checks.

## Traefik

Mount the repository as a local plugin and point the middleware at the identity member:

```yaml
# static configuration
experimental:
  localPlugins:
    beedge:
      moduleName: github.com/brickKit/be-edge/v3   # the repository at /plugins-local/src/github.com/brickKit/be-edge/v3
# dynamic configuration
http:
  middlewares:
    edge:
      plugin:
        beedge:
          identityAddress: be-iam-casdoor:9200      # the identity member's system surface
          identityComponent: infra/iam-casdoor
          deployment: <DEPLOYMENT_ID>
          certFile: /certs/edge.cert.pem            # the service identity infra/edge (deployment mTLS)
          keyFile: /certs/edge.key.pem
          caFile: /certs/ca.pem
          featuresFile: /features/features.json
```

Optional: `featuresPath` (`/api/features`), `logoutPath` (`/api/iam/logout`), `replayLimit` (B_replay, 1 MiB),
`pollInterval` (P_inv, `1s`), `cookieName` (`be_session`).

## Tests

- `go test ./...` and, under Traefik's interpreter, `yaegi test .` (Yaegi v0.16.1, what Traefik v3.0.4 embeds): the
  handler with a fake identity member, the wire messages.
- `cd tests && go test ./...`: the protocol's `edge-flow` vectors through the plugin's entry, over gRPC and mTLS to a
  grpc-go SessionService; a wrong identity member, the poller, certificate rotation.
- `cd tests && go test -tags traefik ./...`: the plugin in a real Traefik v3.0.4 container (needs Docker).
