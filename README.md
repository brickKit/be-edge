# be-edge

The edge's session layer of BrickEnterprise (be-protocol chapter 11): per-session access tokens injected into
browser requests, one replay when the entry component answers `TOKEN_STALE`, the custom header that state-changing
requests need, `features` for logged-in sessions only, and the ended sessions pulled from the identity member's
`be.session.v1.SessionService`.

- a core package that uses the standard library only;
- a Traefik plugin (Yaegi) wrapping it, the default edge;
- a sidecar wrapper for other edge products, held to the same checks.

Work in progress: foundations item 2, task T4 of the assembly project.
