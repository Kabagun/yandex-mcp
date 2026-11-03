# Parent repository review — 2026-11-02

Follow-up: [the 2026-11-03 qualification](upstream-review-2026-11-03.md) applies
the previously deferred HTTP deadline and encoded-path fixes.

The GitHub fork chain is `Kabagun/yandex-mcp` → `denis-samatov/yandex-workspace-mcp`; the parent repository is not itself a fork. Reviewed parent `main` at `cc2753d12e4235c548e1b4e90a5959cdfac0dce1`, relative to shared base `e518d82c6bd4b751af2d21f88ca41c8d4f4e0fa3`.

The parent has no subsequent changes to this fork's shared OAuth implementation or Mail client, so it does not contain a fix for fixed client/grant expiry or destructive refresh-error handling. Disk and Mail share the corrected credential lifecycle in this fork.

## Adapted changes

- [`1570354`](https://github.com/denis-samatov/yandex-workspace-mcp/commit/1570354f53ad7725236ed9f868560d9b1e7ca8bc): bind static bearer tokens to the configured resource and enable SDK token-resource validation in static and multi-user modes. This requires MCP SDK 2.3. The dependency baseline and SDK-compatible public tool errors/schema tests are retained alongside this change.
- The download buffering check from [`6e822e9`](https://github.com/denis-samatov/yandex-workspace-mcp/commit/6e822e934e091ccb789e029312fc0b60163a8e42): reject a chunk before appending it if it would exceed the byte limit. This preserves this fork's official download host allowlist and bounded, independently validated redirects.

## Deferred changes

- [`dd22f9b`](https://github.com/denis-samatov/yandex-workspace-mcp/commit/dd22f9b6f45a5378ddc2c8ec1fa43e9f975e20c2) and [`985a831`](https://github.com/denis-samatov/yandex-workspace-mcp/commit/985a831e890c3779e2bc5f4fa97dab9314c1bd56) add overall API-operation deadlines including credential resolution. These need a separate adaptation for this fork's Mail protocol operations and mutation retry rules.
- The encoded-path normalization portion of `6e822e9` changes path interpretation and should be qualified separately against the fork's root policies and existing paths.
- [`0250779`](https://github.com/denis-samatov/yandex-workspace-mcp/commit/025077965027ca3f99b5dfd7d830d4e01c303bf0) adds exposure tests and another development dependency. Its expected surface covers Disk/Wiki rather than this fork's Mail, profile and attachment-upload extensions.

A wholesale merge would overwrite or conflict with isolated Mail/Disk profiles, account discovery, attachment uploads and signed-transfer policies. Relevant changes were adapted individually.
