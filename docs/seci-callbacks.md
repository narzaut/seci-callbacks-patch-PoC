# SeCiCallbacks — Deep Dive

## Code Integrity Architecture

The Windows kernel enforces code signing through the **Code Integrity (CI)** subsystem. At a high level:

```
NtLoadDriver → IopLoadDriver → MmLoadSystemImage → SeValidateImageHeader
                                                        │
                                                        ▼
                                               SeCiCallbacks[5]
                                               CiValidateImageHeader
                                                        │
                                              ┌─────────┴─────────┐
                                              ▼                   ▼
                                         SUCCESS              FAILURE
                                      driver loads         driver rejected
```

### SeCiCallbacks table layout (x64)

The table is an array of function pointers at a fixed export from ntoskrnl. Each entry is 8 bytes. Known entries:

| Offset | Name | Purpose |
|---|---|---|
| `+0x00` | `CiValidateImageData` | Validates raw PE image data |
| `+0x08` | `CiQueryInformation` | Queries CI policy info |
| `+0x10` | `CiSetPolicyCookie` | Sets CI policy cookie |
| `+0x18` | `CiSendDetectedError` | Reports CI violation |
| `+0x20` | `CiValidateImageHeader` | **Validates PE header for DSE** |
| `+0x28` | `CiHashMemory` | Hashes memory region |

### Runtime behavior

During `NtLoadDriver`:
1. The kernel maps the driver PE image
2. It calls `SeValidateImageHeader(image_data, image_size, ...)`
3. This invokes `CiValidateImageHeader` through the function pointer at `SeCiCallbacks + 0x20`
4. `CiValidateImageHeader` checks the digital signature, certificate chain, and CI policy
5. If validation passes, the driver loads

## The Bypass

### Why it works

`SeCiCallbacks` is in `ntoskrnl.exe`'s `.data` section — read/write pages, no execute permissions, no special protection. The table is populated once at boot by `ci.dll` and never verified again.

The kernel does not:
- Check that `CiValidateImageHeader` actually points to `ci.dll` code
- Hash the table periodically
- Use Control Flow Guard (CFG) for these indirect calls
- Protect the table with hypervisor-level EPT permissions

### PatchGuard blind spot

PatchGuard (Kernel Patch Protection) protects specific structures:
- SSDT (System Service Descriptor Table)
- IDT (Interrupt Descriptor Table)  
- GDT (Global Descriptor Table)
- Certain MSRs (LSTAR, CSTAR, etc.)
- Loaded module list integrity
- Specific code sections (`.text` checksums)

`SeCiCallbacks` is in a writable `.data` section and contains data (function pointers), not code. PatchGuard was designed to detect *code* tampering and critical *system table* modification, not general-purpose function pointer overwrites.

### HVCI / VBS blind spot

Hypervisor-protected Code Integrity runs CI validation inside a secure VTL1 environment. However, the function pointer table (`SeCiCallbacks`) is still in VTL0 kernel memory. HVCI validates the *code being signed*, not the *mechanism that calls the validator*. If you redirect the validator function pointer to a trusted signed function (`ZwFlushInstructionCache`), HVCI sees a signed call path and does not intervene.

## Resolution methods

### Method 1: Export table lookup (most reliable)

Load `ntoskrnl.exe` from `C:\Windows\System32` using `LoadLibraryEx` with `DONT_RESOLVE_DLL_REFERENCES` to avoid triggering loader notifications. Walk the PE export directory to find `SeCiCallbacks` RVA. Compute runtime address as `ntoskrnl_va_base + rva`.

### Method 2: Pattern scan (cross-version)

Search `.text` for LEA instructions referencing addresses in `.data` range:
```asm
lea rcx, [rip + offset_to_SeCiCallbacks]
```
This pattern appears when the CI subsystem registers the callbacks. Fragile across kernel versions but works when exports are missing.

### Method 3: Physical scan (offline)

Parse `ntoskrnl.exe` on disk, compute RVA, add to known physical base from MZ scan. No live module enumeration needed.

## ZwFlushInstructionCache properties

```c
NTSTATUS ZwFlushInstructionCache(
    HANDLE ProcessHandle,   // ignored
    PVOID BaseAddress,      // ignored
    SIZE_T Length           // ignored
);
```

- Returns `STATUS_SUCCESS` when called with `ProcessHandle = -1` (the kernel uses `NtCurrentProcess()` which is `-1`)
- Does not modify any critical kernel state
- Is exported from ntoskrnl, so its address is trivially resolvable
- Has no side effects that affect driver loading
- Is a syscall stub, not a deep CI function — minimal attack surface

## Detection considerations

As of 2026, the following do **not** detect SeCiCallbacks tampering:
- Windows Defender
- CrowdStrike Falcon
- SentinelOne
- Most EDR products

The technique has been public knowledge since at least 2018 (kdmapper, EfiGuard) but detection is difficult because:
1. The write is a single 8-byte write to a writable page
2. The operation is done via physical memory, bypassing virtual memory hooks
3. The table is restored immediately after loading the payload driver
4. No driver load failure or security event is generated — the validation just succeeds
