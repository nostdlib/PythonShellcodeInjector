# PythonShellcodeInjector

> Cross-platform position-independent shellcode loader written in pure Python -- no third-party dependencies.

![Python](https://img.shields.io/badge/Python-2.6%2B%20%7C%203.0%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20FreeBSD%20%7C%20Solaris%20%7C%20Android%20%7C%20iOS-blue)
![Architecture](https://img.shields.io/badge/Arch-x86%20%7C%20x86__64%20%7C%20ARM%20%7C%20AArch64%20%7C%20RISC--V%20%7C%20MIPS64-orange)

---

## Features

- **Zero dependencies** -- uses only the Python standard library (`ctypes`, `mmap`, `urllib`)
- **Cross-platform execution** -- POSIX systems use `mmap` + `mprotect`; Windows uses suspended-process injection via `CreateRemoteThread`
- **Broad architecture support** -- x86, x86_64, ARMv7, AArch64, RISC-V (32/64), and MIPS64
- **Automatic host detection** -- identifies OS, CPU family, and bitness at runtime, including emulated environments (e.g., x86_64 Python on ARM64 Windows)
- **Python 2/3 compatible** -- runs on Python 2.6+ and Python 3.0+ without modification
- **W^X compliant** -- memory is mapped as read-write, shellcode is written, then permissions are flipped to read-execute before transfer of control
- **Payload validation** -- rejects payloads that are too small or that contain HTML (proxy/captive-portal detection)
- **Structured logging** -- timestamped, leveled log output with hex dump diagnostics

## Supported Platforms

| OS | Architectures |
|----|---------------|
| Windows | i386, x86_64, armv7a, aarch64 |
| macOS | x86_64, aarch64 |
| Linux | i386, x86_64, armv7a, aarch64, riscv32, riscv64, mips64 |
| FreeBSD | i386, x86_64, aarch64, riscv64 |
| Solaris | i386, x86_64, aarch64 |
| Android | x86_64, armv7a, aarch64 |
| iOS | aarch64 |

## How It Works

| Platform | Method | Details |
|----------|--------|---------|
| Linux, macOS, FreeBSD, Solaris, Android, iOS | `mmap` + `mprotect` | Maps RW, writes shellcode, flips to RX, calls entry point in-process |
| Windows | Process injection | Creates a suspended `cmd.exe`, allocates memory in the remote process, writes shellcode, flips to RX, and executes via `CreateRemoteThread` |

On POSIX systems the shellcode must match the Python interpreter's bitness (a 32-bit Python downloads and runs 32-bit shellcode). On Windows the injection targets a native-arch host process, so any Python bitness works.

## Requirements

- **Python 2.6+** or **Python 3.0+**
- No third-party packages required
- On POSIX: a kernel that supports `mmap` with `MAP_PRIVATE` and `mprotect` with `PROT_EXEC`
- On Windows: sufficient privileges to call `CreateProcessW` and `CreateRemoteThread`

## Usage

```bash
# Auto-detect platform and architecture, download and execute the latest build:
python loader.py
```

The loader will:

1. Detect the host OS, CPU architecture, and bitness
2. Download the matching shellcode binary from GitHub Releases
3. Validate the payload (size check, HTML rejection)
4. Execute via the appropriate platform method

### Customization

Edit the `URL_TEMPLATE` variable in `loader.py` to point at a different artifact source:

```python
URL_TEMPLATE = "https://example.com/builds/{platform}-{arch}.bin"
```

The `{platform}` and `{arch}` placeholders are replaced at runtime with values like `linux`, `windows`, `x86_64`, `aarch64`, etc.

## SSL Note

SSL certificate verification is disabled. The loader downloads unsigned shellcode from public endpoints, so certificate checks add no meaningful security and break on hosts with outdated CA stores (Windows 7, Solaris, etc.).

## Disclaimer

This tool is provided **strictly for authorized security testing, education, and research purposes**. Unauthorized use of this software against systems you do not own or have explicit written permission to test is illegal and unethical.

By using this software, you agree that you are solely responsible for your actions and that the authors bear no liability for misuse.

See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) for the full responsible use policy.

## License

This project is licensed under the [MIT License](LICENSE).
