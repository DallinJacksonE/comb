# Open source and hosted-service review

Reviewed 2026-11-09. This is an engineering and licensing planning review, not a
security audit or a legal opinion. The owner selected AGPL-3.0-only during this
review; LICENSE and package metadata now reflect that selection.

## Business fit

COMB can support a business selling managed FRAME instances, availability,
storage, relay bandwidth, upgrades, monitoring, and support. Its architecture
also deliberately supports independent self-hosting. Charging for your own
infrastructure does not require preventing free use of the software.

The following implementation details affect that offering:

| Finding | Evidence | Business implication |
| --- | --- | --- |
| Direct replication does not depend on a paid GUARD relay. | `FRAME/src/peer.rs` exchanges pinned Noise messages over HTTP(S); `FRAME/src/daemon.rs` schedules peer sync. | Reachable peers can synchronize without buying relay service. Sell connectivity where needed and managed reliability, rather than mandatory access to collaboration. |
| Users control enrollment, recovery, and replicas. | `FRAME/src/onboarding.rs`, `FRAME/src/restore.rs`, and `system/readme.md`. | Customers can leave with their data. The provider cannot promise identity/password recovery without the customer's required recovery material. |
| A full hosted FRAME is a trusted endpoint. | `FRAME/src/store.rs` accesses unlocked repositories; `GUARD/README.md` distinguishes full FRAMEs from ciphertext storage. | An ordinary provider-controlled running FRAME can expose plaintext and keys to its host. Do not sell it as having the same provider-unreadable properties as a ciphertext-only backup service. |
| GUARD is a library, not a complete commercial service. | `GUARD/Cargo.toml`, `GUARD/src/lib.rs`, `GUARD/README.md`. | A public service needs a deployable API/control layer, customer authentication, provisioning, metering, billing, and operations. FRAME does not currently use a TURN client or implement ICE. |
| Backup storage has object limits but no customer ownership or total quotas. | `GUARD/src/backup.rs`: `BlobStore`, `put_ciphertext`, `get`. | Place it behind an authenticated service that enforces tenant ownership, aggregate storage limits, retention, deletion, and accounting. A blob hash must not become customer authorization. |
| The coturn generator supplies one static credential and fixed limits. | `GUARD/src/turn.rs`: `CoturnConfig::render` uses `lt-cred-mech`, `user`, fixed user/total quotas and bandwidth limits. | Add customer-specific credential lifecycle and usage accounting before selling shared relay access. It has authentication, but no subscription entitlement checks. |
| Remote hosting needs the dedicated authenticated endpoint. | `FRAME/src/daemon.rs`, `FRAME/src/web_host.rs`, `FRAME/HTTPS.md`. | Keep the local browser listener private. Use documented HTTPS hosting and isolate each customer's process, state, keys, and resources until a reviewed shared tenancy design exists. |

These are product and deployment gaps, not evidence of intentional sabotage.
This review does not establish production security or exhaustively inspect every
code path. No code needs to be removed solely to permit charging for hosting.

## License recommendation

Prefer **AGPL-3.0-only** if the goal is free use and contributions while requiring
operators of modified network versions to offer the corresponding source to
their remote users. It permits paid hosting, including hosting by competitors.
It does not require competitors to submit pull requests to this repository.

Prefer **MIT** if broad adoption and allowing private modifications matter more
than reciprocity. MIT also permits competing commercial hosting.

An open source license cannot reserve commercial hosting exclusively to your
business. A restriction such as “free except competing hosted services” would
require a different, source-available licensing approach. Brand protection and
service contracts are separate from the software license.

Primary references:

- AGPL text, especially section 13: <https://www.gnu.org/licenses/agpl-3.0.html>
- Open Source Definition: <https://opensource.org/osd>
- MIT text: <https://choosealicense.com/licenses/mit/>

## Current license state and release work

Before this change, `Cargo.toml` declared MIT, inherited by all three crates,
there was no tracked LICENSE file, and the GUI lacked a license field. Do not assume
this inconsistency means earlier recipients have no MIT rights. A new license
cannot simply withdraw rights already validly granted in previous releases.

Before releasing under the chosen license:

1. Confirm ownership and permission to license all original and contributed
   material, including any copied snippets or assets. Git authorship alone does
   not prove ownership or employer permission.
2. Add the complete standard LICENSE text; align Cargo and GUI package metadata
   and the README. For AGPL, add a prominent source access mechanism for deployed
   modified network versions, covering the actual running version and required
   corresponding source/build material.
3. Add CONTRIBUTING instructions stating contributions use the project license
   and contributors must have permission. A DCO sign-off can record this; it
   does not transfer copyright or grant blanket proprietary relicensing rights.
   If future proprietary dual licensing is desired, resolve contribution rights
   before accepting contributions.
4. Preserve dependency licenses, copyright notices, and required notices/source
   when distributing binaries or browser bundles. Include deployment/container
   components in the release compliance review.

An offline metadata review of Cargo.lock's resolved packages found declared
licenses for all Rust dependencies, with permissive alternatives available in
the listed expressions. The GUI lockfile includes MIT, Apache, ISC, BSD, and
MPL-2.0 declarations. These declarations do not establish compliance: inspect
actual notices, bundled assets, selected build dependencies, and distributed
artifacts. Dependencies retain their own licenses; the project license does not
replace them. Git and coturn are external programs and need a separate review
if included in installers, images, or other distributed packages.
