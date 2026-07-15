# Codex Desktop Mirror

This public repository is an automated, unmodified mirror of Codex-labelled Desktop installers obtained through the source endpoints listed below. Anonymous users can download every published asset directly from GitHub Releases.

## Stable latest downloads

- [Codex-macOS-arm64.dmg](https://github.com/ding-rs/codex-desktop-mirror/releases/latest/download/Codex-macOS-arm64.dmg)
- [Codex-macOS-x64.dmg](https://github.com/ding-rs/codex-desktop-mirror/releases/latest/download/Codex-macOS-x64.dmg)
- [Codex-Windows-x64.msix](https://github.com/ding-rs/codex-desktop-mirror/releases/latest/download/Codex-Windows-x64.msix)
- [Codex-Windows-Installer.exe](https://github.com/ding-rs/codex-desktop-mirror/releases/latest/download/Codex-Windows-Installer.exe)
- [manifest.json](https://github.com/ding-rs/codex-desktop-mirror/releases/latest/download/manifest.json)
- [SHA256SUMS](https://github.com/ding-rs/codex-desktop-mirror/releases/latest/download/SHA256SUMS)

## Source endpoints

The mirror tracks the two Codex DMG product endpoints, the Microsoft installer wrapper, and Store package metadata resolved for the Codex product ID:

- Apple silicon macOS DMG: `https://persistent.oaistatic.com/codex-app-prod/Codex.dmg`
- Intel macOS DMG: `https://persistent.oaistatic.com/codex-app-prod/Codex-latest-x64.dmg`
- Third-party Microsoft Store metadata resolver for product `9PLM9XGG6VKS`: `https://msft-store.tplant.com.au/api/Packages?inputform=productid&Id=9PLM9XGG6VKS&environment=Production`
- Microsoft installer wrapper: `https://get.microsoft.com/installer/download/9PLM9XGG6VKS?cid=website_cta_psi`

The third-party Store resolver is used only to resolve package metadata by product ID. Its response contains a temporary MSIX delivery URL, which is accepted only when it uses a reviewed Microsoft delivery host.

## Synchronization model

The scheduled check performs one HTTPS metadata `GET` and three HTTPS `HEAD` requests. If the source fingerprints have not changed, it downloads zero installer bodies and performs zero release writes.

When a source changes, only changed installers are downloaded from the source endpoints. Unchanged installers are retrieved from the previous GitHub Release. Every staged asset is hashed locally with SHA-256 before upload; reused assets are additionally compared with the hash recorded by the previous release manifest. The workflow assembles a complete snapshot as a draft, verifies the remote draft's exact asset names and sizes, and only then publishes it as the new `latest` release. Older releases are retained for rollback.

Every automatic and manually dispatched synchronization uses the same repository concurrency lock. This single-writer rule, together with per-run ownership markers, ensures that cleanup can remove only a draft owned by the current run. A failure before publishing leaves the previous `latest` release intact. If the publish outcome is unknown, cleanup refuses to delete the new release because it may already be published.

## Security and integrity

- Every release includes `manifest.json` and `SHA256SUMS`. Every staged asset's SHA-256 is computed locally before upload; reused assets must additionally match their previously recorded hashes.
- Each installer must be smaller than 2 GiB.
- The Windows runner uses Windows SDK `signtool` to perform Authenticode trust-chain verification for both MSIX and EXE assets; it does not pin a specific publisher identity.
- MSIX downloads must match the metadata `expectedSize` and a reviewed Microsoft `delivery.mp.microsoft.com` host.
- A Store CDN URL using HTTP is requested only when its MSIX changed. Probe-only and no-change checks never request that delivery URL.
- Failures before publish preserve the previous `latest`. When publication state cannot be confirmed, the possibly published new release is never deleted; owned draft cleanup and workflow serialization prevent one run from deleting another run's work.

## Maintainer checks

Run the test suite locally:

```sh
pnpm test
```

Probe upstream metadata without downloading installer bodies or writing a release:

```sh
pnpm sync -- --probe-only
```

A normal synchronization is intended for the serialized Windows GitHub Actions job. It additionally requires `GH_TOKEN`, `GH_REPO`, and Windows SDK `signtool`.
