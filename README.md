# integrity-vhd

[![Build status](https://github.com/microsoft/integrity-vhd/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/microsoft/integrity-vhd/actions?query=branch%3Amaster)

This package contains tools to convert tar files into VHDs and to add integrity information to those VHDs. It has been split out of https://github.com/microsoft/hcsshim to allow it to be consumed in tooling.

## Overview

`dmverity-vhd` is a command-line tool for creating integrity-protected container layer images:
- **Linux**: Creates VHD files with dm-verity superblock and merkle tree
- **Windows**: Creates CIM (Composite Image) files with Block CIM integrity checksums

The tool supports both platforms and can process container images from registries, Docker daemon, or tarballs.

## Building

### Linux Binary
```sh
GOOS=linux go build -o dmverity-vhd ./cmd/dmverity-vhd
```

### Windows Binary
```sh
GOOS=windows go build -o dmverity-vhd.exe ./cmd/dmverity-vhd
```

Or using PowerShell:
```powershell
$env:GOOS="windows"
go build -o dmverity-vhd.exe .\cmd\dmverity-vhd
```

## Commands

The tool provides four main commands:

| Command | Description |
|---------|-------------|
| `create` | Create layer VHD files (Linux) or CIM files (Windows) |
| `roothash` | Compute root hashes for each layer without creating files |
| `hashlayer` | Compute root hash for a single layer tar file |
| `tar2hashed` | Convert a tar file to integrity-protected ext4 or CIM |

## Usage Examples

### Global Flags

These flags must be placed **before** the command:

```bash
--verbose, -v          # Verbose output
--trace, -vv           # Trace output
--docker, -d           # Use local Docker daemon instead of registry
--tarball, -t PATH     # Path to tarball containing image
--buffered-reader, -b  # Use buffered opener for image
--profiler FILE        # Enable profiling and save to file
```

### `create` - Create Layer Files

Creates VHD files (Linux) or CIM files (Windows) for each layer of a container image.

#### Linux Examples

```bash
# From container registry
./dmverity-vhd create \
  -i alpine:latest \
  -o ./output \
  --platform linux/amd64

# From tarball (OCI/Docker image tar)
./dmverity-vhd --tarball nginx-alpine.tar create \
  -o ./output \
  --platform linux/amd64

# From local Docker daemon
./dmverity-vhd -d create \
  -i alpine:latest \
  -o ./output \
  --platform linux/amd64

# With separate hash device VHD
./dmverity-vhd create \
  -i alpine:latest \
  -o ./output \
  --platform linux/amd64 \
  --hash-dev-vhd

# With registry authentication
./dmverity-vhd create \
  -i myregistry.azurecr.io/myimage:tag \
  -u username \
  -p password \
  -o ./output \
  --platform linux/amd64
```

#### Windows Examples

```bash
# From container registry
./dmverity-vhd.exe create \
  -i mcr.microsoft.com/windows/nanoserver:ltsc2025 \
  -o ./output \
  --platform windows/amd64

# From tarball (OCI image tar)
./dmverity-vhd.exe --tarball nanoserver.tar create \
  -o ./output \
  --platform windows/amd64
```

#### Create Command Flags

```bash
-i, --image, --input   # Container image reference (optional with --tarball)
-o, --out-dir          # Output directory (required)
-u, --username         # Registry username
-p, --password         # Registry password
--platform             # Image platform (default: linux/amd64)
--hash-dev-vhd, --hdv  # Save hash device as separate VHD (Linux only)
--data-vhd, --dir      # Save directory tarfile as VHD (Linux only)
```

### `roothash` - Compute Root Hashes

Computes the root hash for each layer without creating VHD/CIM files. Useful for verification or comparison. Outputs JSON format for easy integration with other tools.

#### Linux Examples

```bash
# From container registry
./dmverity-vhd roothash \
  -i alpine:latest \
  --platform linux/amd64

# From tarball
./dmverity-vhd --tarball nginx-alpine.tar roothash \
  --platform linux/amd64

# From Docker daemon
./dmverity-vhd -d roothash \
  -i alpine:latest \
  --platform linux/amd64
```

#### Windows Examples

These work on both PowerShell and WSL2 provided you have `CimWriter.dll` in `C:\Windows\System32`. For deterministic hashes, use Windows Server 2025 or later.

```bash
# From container registry
./dmverity-vhd.exe roothash \
  -i mcr.microsoft.com/windows/nanoserver:ltsc2025 \
  --platform windows/amd64

# From tarball (shows individual layer hashes + merged hash for multi-layer images)
./dmverity-vhd.exe --tarball nanoserver.tar roothash \
  --platform windows/amd64
```

#### Output Format

**Linux Output (JSON):**
```json
{
  "layers": [
    "75f76b2620207ef52a83803bb27b3243a51b13304950ee97fd4a2540cd2f465f",
    "d7adf568bac4ee8b05efd56775ce1504a66834781b189a8067ab5b71f513d440",
    "e3701df664d4fc1d5bd68ef5e5f82d66b67bd13038822b1adb8de22cc24915ac"
  ]
}
```

**Windows Output (JSON):**

For single-layer images:
```json
{
  "layers": [
    "75f76b2620207ef52a83803bb27b3243a51b13304950ee97fd4a2540cd2f465f"
  ],
  "mounted_cim": [
    "75f76b2620207ef52a83803bb27b3243a51b13304950ee97fd4a2540cd2f465f"
  ]
}
```

For multi-layer images:
```json
{
  "layers": [
    "24af9c8b208189c4846926c47963835daecfbd71168d15da1af247c749b58873",
    "24980812fb450c07daea8b3c72e78ade540b48cd59b649a181cac189fe93e22d"
  ],
  "mounted_cim": [
    "849f1104f01c006729222c65e014eb4070608e75b9860f3411ca4b5a77b658c5"
  ]
}
```

**Field Descriptions:**
- `layers`: Array of root hashes for each layer in the image (in order)
- `mounted_cim`: (Windows only) The hash of the mounted/merged CIM filesystem. For single-layer images, this is the same as the layer hash. For multi-layer images, this is the merged CIM hash.

#### Roothash Command Flags

```bash
-i, --image, --input   # Container image reference (optional with --tarball)
-u, --username         # Registry username
-p, --password         # Registry password
--platform             # Image platform (default: linux/amd64)
```

### `hashlayer` - Hash Single Layer

Computes the root hash for a single layer tar file. Does not support container images (use `roothash` for that).

#### Examples

```bash
# Linux layer
./dmverity-vhd hashlayer \
  -t layer.tar \
  --platform linux/amd64

# Windows layer
./dmverity-vhd.exe hashlayer \
  -t layer.tar.gz \
  --platform windows/amd64

# Supports gzip-compressed tars
./dmverity-vhd hashlayer \
  -t layer.tar.gz \
  --platform linux/amd64
```

#### Output Example

```
71702a459fa5e6574337e014d9d3936bcf7cb448aaffe3814883caa01fbb4827
```

#### Hashlayer Command Flags

```bash
-t, --input            # Path to layer tar file (required)
--platform             # Image platform (default: linux/amd64)
```

### `tar2hashed` - Convert Tar to Integrity-Protected Format

Converts a single tar file to either ext4 (Linux) or CIM (Windows) with integrity protection.

#### Examples

```bash
# Linux: Convert to ext4 with dm-verity
./dmverity-vhd tar2hashed \
  -i layer.tar \
  -o layer.ext4 \
  -t ext4

# Windows: Convert to CIM
./dmverity-vhd.exe tar2hashed \
  -i layer.tar \
  -o layer.cim \
  -t cim
```

#### Tar2hashed Command Flags

```bash
-i, --input            # Path to layer tar file (required)
-o, --output           # Path to output file (required)
-t, --type             # Output type: "ext4" or "cim" (required)
```

## Platform Support

### Linux (`--platform linux/amd64`)
- Creates `.vhd` files with dm-verity integrity protection
- Merkle tree and superblock embedded in VHD
- Can use `--hash-dev-vhd` to separate hash device
- `roothash` command outputs JSON with `layers` array

### Windows (`--platform windows/amd64`)
- Creates `.bcim` files (Block CIM format)
- Integrity checksums embedded in CIM structure
- Multi-layer images generate merged CIM hash for the actual mounted filesystem
- `roothash` command outputs JSON with `layers` array and `mounted_cim` field

**Note:** Windows CIM creation requires the Windows CimWriter.dll. On Linux, you can use WSL2 to run the `.exe` binary. For deterministic hashes on image repull, you need to use this tool on Windows Server 2025 or later.

## Output Files

### Linux Create Output
```
output/
├── layer1-diffid.vhd
├── layer2-diffid.vhd
└── layer3-diffid.vhd
```

With `--hash-dev-vhd`:
```
output/
├── layer1-diffid.vhd
├── layer1-diffid.hash-dev.vhd
├── layer2-diffid.vhd
└── layer2-diffid.hash-dev.vhd
```

### Windows Create Output
```
output/
├── layer1-diffid.bcim
├── layer2-diffid.bcim
└── layer3-diffid.bcim
```

## Troubleshooting

### "layer VHD does not exist" Error

Ensure you're using the correct platform flag and that temp directory has sufficient space.

### "pattern contains path separator" Error

This was fixed in recent versions. Ensure you're using an up-to-date build.

### Windows CIM Creation Fails on Linux

Run the Windows binary (`.exe`) in WSL2, or run directly on a Windows host (WS2025).

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Microsoft CLA](https://cla.microsoft.com).

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

We require that contributors sign their commits
to certify they either authored the work themselves or otherwise have permission to use it in this project.

We also require that contributors sign their commits using  using [`git commit --signoff`][git-commit-s]
to certify they either authored the work themselves or otherwise have permission to use it in this project.
A range of commits can be signed off using [`git rebase --signoff`][git-rebase-s].

Please see  [the developer certificate](https://developercertificate.org) for more info,
as well as to make sure that you can attest to the rules listed.
Our CI uses the [DCO Github app](https://github.com/apps/dco) to ensure that all commits in a given PR are signed-off.

### Linting

Code must pass a linting stage, which uses [`golangci-lint`][lint].
Since `./test` is a separate Go module, the linter is run from both the root and the
`test` directories. Additionally, the linter is run with `GOOS` set to both `windows` and
`linux`.

The linting settings are stored in [`.golangci.yaml`](./.golangci.yaml), and can be run
automatically with VSCode by adding the following to your workspace or folder settings:

```json
    "go.lintTool": "golangci-lint",
    "go.lintOnSave": "package",
```

Additional editor [integrations options are also available][lint-ide].

Alternatively, `golangci-lint` can be [installed][lint-install] and run locally:

```shell
# use . or specify a path to only lint a package
# to show all lint errors, use flags "--max-issues-per-linter=0 --max-same-issues=0"
> golangci-lint run
```

To run across the entire repo for both `GOOS=windows` and `linux`:

```powershell
> foreach ( $goos in ('windows', 'linux') ) {
    foreach ( $repo in ('.', 'test') ) {
        pwsh -Command "cd $repo && go env -w GOOS=$goos && golangci-lint.exe run --verbose"
    }
}
```

### Go Generate

The pipeline checks that auto-generated code, via `go generate`, are up to date.
Similar to the [linting stage](#linting), `go generate` is run in both the root and test Go modules.

This can be done via:

```shell
> go generate ./...
> cd test && go generate ./...
```

## Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Dependencies

This project requires Golang 1.18 or newer to build.

For system requirements to run this project, see the Microsoft docs on [Windows Container requirements](https://docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/system-requirements).

## Reporting Security Issues

Security issues and bugs should be reported privately, via email, to the Microsoft Security
Response Center (MSRC) at [secure@microsoft.com](mailto:secure@microsoft.com). You should
receive a response within 24 hours. If for some reason you do not, please follow up via
email to ensure we received your original message. Further information, including the
[MSRC PGP](https://technet.microsoft.com/en-us/security/dn606155) key, can be found in
the [Security TechCenter](https://technet.microsoft.com/en-us/security/default).

For additional details, see [Report a Computer Security Vulnerability](https://technet.microsoft.com/en-us/security/ff852094.aspx) on Technet

---------------
Copyright (c) 2018 Microsoft Corp.  All rights reserved.

[lint]: https://golangci-lint.run/
[lint-ide]: https://golangci-lint.run/usage/integrations/#editor-integration
[lint-install]: https://golangci-lint.run/usage/install/#local-installation

[git-commit-s]: https://git-scm.com/docs/git-commit#Documentation/git-commit.txt--s
[git-rebase-s]: https://git-scm.com/docs/git-rebase#Documentation/git-rebase.txt---signoff
