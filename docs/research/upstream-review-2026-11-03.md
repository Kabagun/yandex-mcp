# Upstream and reference-source qualification — 2026-11-03

The GitHub fork chain remains `Kabagun/yandex-mcp` →
`denis-samatov/yandex-workspace-mcp`. The parent is not itself a fork. After
fetching all remotes, parent `main` is still
`cc2753d12e4235c548e1b4e90a5959cdfac0dce1`, unchanged since the November 2 review.
The additional projects below are reference implementations, rather than Git
parents. Comparisons use the pinned baselines in
[the original reference review](reference-repositories-2026-08-30.md).

## Changes qualified and applied

- Parent [`dd22f9b`](https://github.com/denis-samatov/yandex-workspace-mcp/commit/dd22f9b6f45a5378ddc2c8ec1fa43e9f975e20c2)
  and [`985a831`](https://github.com/denis-samatov/yandex-workspace-mcp/commit/985a831e890c3779e2bc5f4fa97dab9314c1bd56):
  each HTTP API call now shares its operation deadline across credential lookup,
  response reading, retries and backoff. The adaptation also bounds a slow custom
  retry sleeper. Only expiry of our cancellation scope becomes `UpstreamTimeout`;
  unrelated `TimeoutError` and external cancellation retain their behavior.
  Mutations and signed uploads remain single-attempt operations.
- The remaining path-policy portion of parent
  [`6e822e9`](https://github.com/denis-samatov/yandex-workspace-mcp/commit/6e822e934e091ccb789e029312fc0b60163a8e42):
  decode percent escapes once and reject encoded separators, dots, percent signs
  and control bytes. Previously an upstream path such as
  `/Personal/%2E%2E/Work/file` could appear under the allowed `/Work` root after
  normalization. The stricter rule applies to input and returned paths; ordinary
  names, spaces and encoded UTF-8 remain supported. Normalization is idempotent.

The parent's MIT license and original copyright notice are retained. No code
from the other reference implementations was copied. No dependency update is
needed. Existing isolated profiles, public tool schemas, OAuth persistence,
Mail submission semantics and signed-transfer host/redirect policies are kept.

## Reference updates

| Reference | Verified current head | Changes since pinned baseline | Decision |
|---|---|---:|---|
| dlbolshov/yandex-wiki-search-mcp | [`9bc85ee`](https://github.com/dlbolshov/yandex-wiki-search-mcp/commit/9bc85ee5e650e4fe2816d1209b08397c4cae4c93), 1.6.0 | 14 commits | OAuth, public-error and DNS-rebinding fixes corroborate behavior already covered here. Its sliding client expiry and `invalid_client` mapping are unsuitable replacements for our persistent registrations and error categories. Apache-2.0/NOTICE obligations would apply to source copying. |
| APonkratov/yandex-wiki-mcp | [`18f033f`](https://github.com/APonkratov/yandex-wiki-mcp/commit/18f033f0f76bf4d31827df7849e8e0520d4072f9) | 0 | Unchanged. |
| slartus/mcp-yandex-wiki | [`f1a0f04`](https://github.com/slartus/mcp-yandex-wiki/commit/f1a0f041ea3ae49d2d463e970dc0c1e1a3ee1eb6) | 0 | Unchanged. |
| n-r-w/yandex-mcp | [`c29e6ea`](https://github.com/n-r-w/yandex-mcp/commit/c29e6ea695e713137cea8733dea7c7a1dae4f3e2) | 4 commits | Whole-tool cancellation/deadlines are useful future design evidence. Workstation SSH authentication and raw-error propagation do not fit this server. |
| bim-ba/ycli | [`3599fd9`](https://github.com/bim-ba/ycli/commit/3599fd9140ca9a622f4804c28fab6faab4ac04de), 0.142.0 lockfile | 720 commits | Still Tracker/Wiki/Forms/DataLens, with no Disk or IMAP/SMTP client. Optional dry-run planning and organization-bound continuation tokens need separate product decisions; mutation retries must not be copied. |
| Patr56/yadisk-mcp | [`ce98ecb`](https://github.com/Patr56/yadisk-mcp/commit/ce98ecbc12e8dbea4544a6c43715d15933b914d8) | 0 | Primary Disk feature-inventory reference is unchanged. |
| gorokhovdenis/yandex-disk-mcp | [`0e8122a`](https://github.com/gorokhovdenis/yandex-disk-mcp/commit/0e8122a915b88e96d4a6e78c3556d0a65d145573), 0.4.0 | 3 commits | Recursive comparison and checksum-verified transfers are useful future local-only features. Its redirect handling, local-path operations and global jobs do not meet our remote principal/root/transfer policies. |
| theYahia/yandex-360-mcp | [`354d6e2`](https://github.com/theYahia/yandex-360-mcp/commit/354d6e240581865960685e3168956e97d9e41df7) | 0 | Archived; successor checked separately below. |
| yandex-cloud/mcp | [`28e6c80`](https://github.com/yandex-cloud/mcp/commit/28e6c80729e9cb8f07ab7061617a0a91cc5f7409) | 0 | Official proxy/deployment reference is unchanged. |

The archived Yandex 360 project's README points to
[`theYahia/YaAll@5afca94`](https://github.com/theYahia/YaAll/tree/5afca94c6d9613515fc7deb7deee4b93ffbc82c1/mcp/yandex-360-mcp).
Its `src/client.ts`, `src/tools/disk.ts` and `src/tools/email.ts` have identical
Git blob hashes to the original pinned reference. The move therefore hides no
new Disk/Mail fix. Its Mail REST wrapper is not an IMAP/SMTP contract reference.

All nine reference repositories report `fork=false`; this does not establish
independent provenance. In particular, dlbolshov's NOTICE attributes its base to
APonkratov. License/provenance checks are required before any later source copy.

## Scope and remaining work

Default-branch heads, exact commit comparisons and relevant source files were
checked, including the full ycli diff inventory of 1,945 changed files. The ycli
review focused on service inventory and generic improvements, not every changed
line. Unmerged pull requests and live tenant behavior were not evaluated.

The synchronous Mail protocol client needs its own design before extending an
overall deadline through multi-stage IMAP/SMTP and uncertain send outcomes.
Parent `0250779` adds exposure tests and a development dependency for its narrower
Disk/Wiki surface; our Mail/profile/upload tools require different expectations.
Neither change is imported in this qualification.
