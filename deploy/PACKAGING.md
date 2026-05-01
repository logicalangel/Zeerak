# Packaging

Zeerak ships official packages for the Tier 1 distros (VISION §11 Q9):
Debian/Ubuntu, Fedora, Arch, Alpine, plus a Homebrew tap (CLI on macOS),
and a multi-arch GHCR image.

## Automated (every `v*` tag)

[`.github/workflows/release.yml`](../.github/workflows/release.yml) runs
[goreleaser](https://goreleaser.com) which produces:

| Artifact                                                        | Source                           | Where it lands                                                                    |
| --------------------------------------------------------------- | -------------------------------- | --------------------------------------------------------------------------------- |
| `*.tar.gz`, `SHA256SUMS`, SBOMs                                 | `archives:` + `sboms:`           | GitHub Release                                                                    |
| `*.deb`                                                         | `nfpms:`                         | GitHub Release                                                                    |
| `*.rpm`                                                         | `nfpms:`                         | GitHub Release                                                                    |
| `*.apk`                                                         | `nfpms:`                         | GitHub Release                                                                    |
| `ghcr.io/logicalangel/zeerak:<ver>` (linux/amd64 + linux/arm64) | `dockers:` + `docker_manifests:` | GHCR                                                                              |
| `Formula/zeerak.rb`                                             | `brews:`                         | [`logicalangel/homebrew-zeerak`](https://github.com/logicalangel/homebrew-zeerak) |

The release workflow needs one extra repo secret beyond the default
`GITHUB_TOKEN`:

- `HOMEBREW_TAP_GITHUB_TOKEN` — a PAT with `repo` scope on
  `logicalangel/homebrew-zeerak`. Without it, the brew step is a no-op
  and the rest of the release still completes.

## Manual (one-time setup, then per-release upload)

The targets below require maintainer accounts on third-party services and
can't be fully automated from the upstream repo.

### Ubuntu PPA — Launchpad

1. Create the team `~logicalangel` and the PPA `zeerak` on Launchpad.
2. Upload your GPG key to Launchpad and to your local keyring.
3. From a clean checkout of the tag:
   ```sh
   cp -r deploy/ppa/debian ./debian
   debuild -S -sa
   dput ppa:logicalangel/zeerak ../zeerak_*_source.changes
   ```
4. Launchpad rebuilds the source package on its own infrastructure for
   each supported Ubuntu series.

The `debian/` scaffold under [`deploy/ppa/debian/`](./ppa/debian/) is
deliberately minimal — see `control`, `rules`, `changelog`, `install`.
Bump `debian/changelog` for every release; the rest is stable.

### Fedora COPR

1. Create the COPR project `logicalangel/zeerak` (web UI or `copr-cli create`).
2. Trigger a build from the spec file:
   ```sh
   copr-cli build logicalangel/zeerak \
       --packageless \
       deploy/copr/zeerak.spec
   ```
3. Or wire up the Packit / COPR webhook integration so every tag triggers
   a rebuild. The spec file pulls the source tarball from GitHub Releases,
   so it needs the goreleaser job to finish first.

Spec lives at [`deploy/copr/zeerak.spec`](./copr/zeerak.spec) and the chroot
list at [`deploy/copr/copr.conf`](./copr/copr.conf).

### Arch User Repository (AUR)

The binary package `zeerak-bin` lives at
[`deploy/aur/PKGBUILD`](./aur/PKGBUILD). It pulls the published linux
tarballs from GitHub Releases.

To publish:

```sh
cd /tmp && git clone ssh://aur@aur.archlinux.org/zeerak-bin.git
cp ~/Dev/Zeerak/deploy/aur/PKGBUILD       zeerak-bin/
cp ~/Dev/Zeerak/deploy/aur/zeerak-bin.install zeerak-bin/
cd zeerak-bin
sed -i "s/^pkgver=.*/pkgver=${NEW_VERSION}/" PKGBUILD
updpkgsums
makepkg --printsrcinfo > .SRCINFO
git commit -am "v${NEW_VERSION}"
git push
```

A `aur-publish.yml` GitHub Action automating these steps is tracked for
v0.3.

## Verifying installs

```sh
# Debian/Ubuntu
sudo apt install ./zeerak_<ver>_amd64.deb
zeerak --version

# Fedora / RHEL
sudo dnf install ./zeerak-<ver>.x86_64.rpm

# Alpine
sudo apk add --allow-untrusted zeerak-<ver>.apk

# Arch (AUR)
yay -S zeerak-bin

# Homebrew (macOS / Linuxbrew)
brew install logicalangel/zeerak/zeerak

# Container
docker pull ghcr.io/logicalangel/zeerak:<ver>
```

After install:

```sh
sudo systemctl enable --now zeerak-server      # systemd distros
zeerak status
xdg-open http://127.0.0.1:7878/                # web panel
```
