---
title: Showing only namespaces the user can access
sidebar_label: Namespace visibility
---

Kubernetes RBAC cannot restrict the `list` verb to a subset of namespaces.
Multi-tenant platforms therefore often grant `list` on namespaces to every
user (otherwise dashboards cannot populate a namespace selector at all) while
real access is granted per namespace through `RoleBinding`s. With such a
setup, Headlamp's namespace selector shows **every** namespace in the cluster,
including the ones a user cannot do anything with.

The `-require-namespace-get` option makes Headlamp behave like
[Kiali's `require_namespace_get` feature flag](https://kiali.io/docs/configuration/rbac/):
a namespace is shown only if the user is allowed to `get` it.

## Configuration

Enable the option on the Headlamp server:

- `-require-namespace-get=true` or env var `HEADLAMP_CONFIG_REQUIRE_NAMESPACE_GET=true`

With Helm:

```yaml
config:
  extraArgs:
    - -require-namespace-get=true
```

The option is off by default and has no effect on clusters that are accessed
with the service account token (`-unsafe-use-service-account-token`), because
there is no per-user identity to check in that case.

## How it works

For every namespace returned by `GET /api/v1/namespaces`, the backend performs
`GET /api/v1/namespaces/<name>` **with the user's own token** and removes the
namespaces that answer `403 Forbidden` (or `404 Not Found`). The checks take
the same route as the user's own requests, so they also work when cluster
traffic is sent through an [OIDC API proxy](./oidc-api-proxy.md).

Namespace watches receive the same treatment: watch events for namespaces the
user cannot `get` are dropped before they reach the browser. This applies to
both the per-request WebSocket watches and the WebSocket multiplexer.

Decisions are cached per user token for 30 seconds, so the extra `GET`
requests are only issued on the first listing and after the cache expires. Up
to 8 checks run in parallel.

## Checking access with a SelfSubjectAccessReview

The `get` check only works when users cannot `get` namespaces cluster-wide.
Many platforms grant `get` together with `list` on namespaces through a
`ClusterRole`, so that namespace selectors work. Every `GET` then succeeds and
nothing is filtered, even though the user can only work in the namespaces
bound to them with `RoleBinding`s.

For such setups, check access with a `SelfSubjectAccessReview` instead:

- `-namespace-access-check=ssar` or env var `HEADLAMP_CONFIG_NAMESPACE_ACCESS_CHECK=ssar`

A namespace is then shown only if the user may perform the configured verb on
the configured resource **in that namespace**. By default this is `list pods`:

| Flag | Env var | Default |
| --- | --- | --- |
| `-namespace-access-ssar-verb` | `HEADLAMP_CONFIG_NAMESPACE_ACCESS_SSAR_VERB` | `list` |
| `-namespace-access-ssar-resource` | `HEADLAMP_CONFIG_NAMESPACE_ACCESS_SSAR_RESOURCE` | `pods` |
| `-namespace-access-ssar-group` | `HEADLAMP_CONFIG_NAMESPACE_ACCESS_SSAR_GROUP` | empty (core group) |

Pick a permission that every role meant to "see" a namespace has there, and
that cluster-wide roles handed to everyone do not. With Helm:

```yaml
config:
  extraArgs:
    - -require-namespace-get=true
    - -namespace-access-check=ssar
    - -namespace-access-ssar-verb=list
    - -namespace-access-ssar-resource=pods
```

The reviews are sent with the user's own token along the same route as the
user's requests, including an [OIDC API proxy](./oidc-api-proxy.md), and are
cached and run in parallel exactly like the `get` checks. Creating
`SelfSubjectAccessReview`s is allowed for every authenticated user by the
default `system:basic-user` ClusterRole. If a review cannot be completed, the
listing fails closed as described below.

`-namespace-access-check=ssar` requires `-require-namespace-get=true`.

## Safety

- The filter fails closed. If any access check returns an unexpected error the
  whole listing is answered with `502 Bad Gateway` instead of an unfiltered
  list, and a namespace watch is closed instead of forwarding an event that
  could not be checked. The frontend simply retries.
- Namespaces are hidden, not protected: a user who can `list` namespaces can
  still enumerate them with `kubectl`. Use this option to keep the UI focused
  on the user's namespaces, not as an authorization boundary. Authorization is
  enforced by the Kubernetes API server (or your API proxy) as usual.

## Limitations

- Users who are not allowed to `list` namespaces at all still get a `403` from
  the cluster; this option does not synthesise a list for them.
- Resource lists in the *All namespaces* view are still requested cluster-wide
  and are subject to the user's RBAC. Users without cluster-wide read access
  should pick a namespace, or configure the per-cluster
  **Allowed namespaces** setting in the Headlamp UI.
- Very large clusters pay one `GET` per namespace per user every 30 seconds
  at most. The checks are cheap for the API server, but you may notice a short
  delay the first time the namespace list is loaded.
