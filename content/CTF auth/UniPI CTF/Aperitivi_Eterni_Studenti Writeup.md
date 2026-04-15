
**Category:** Crypto / Reverse Engineering
**Difficulty:** Hard
**Solves:** 0
**Author:** Me
**Flag:** `unipi{Crypt0_0_r3v?BOTH}`

## Tags
#crypto #aes #aesround #rev

---

## Overview

*Aperitivi Eterni Studenti* is a cryptography challenge I designed around a deliberately weakened variant of AES-128. The name is a play on the Italian university ritual of never ending aperitivi, because there's always time for another round (and another commit). The challenge sat at the intersection of reverse engineering and applied mathematics: players were given a compiled binary alongside several plaintext/ciphertext pairs and an encrypted flag, and they had to figure out *what* the binary does and *how* to exploit its broken crypto.

It received zero solves during the competition, which I attribute to the fact that not everyone has experience in CTF style challenges, and, in my view, it wasn't something LLMs could easily solve at the time.

## What the Challenge Ships

Contestants receive the following files:

| File | Description |
|---|---|
| `Aperitivi_Eterni_Student` | ELF 64-bit x86-64 binary (the encryptor) |
| `p1.bin` | Known plaintext 1: `AES_SECURITY_TEST` (truncated to 16 bytes) |
| `p2.bin` | Known plaintext 2: `ISCRIVITI_A_CYBE` (truncated to 16 bytes) |
| `c1.bin` | Ciphertext of `p1.bin` |
| `c2.bin` | Ciphertext of `p2.bin` |
| `flag.enc` | Hex-encoded encrypted flag (32 bytes → 2 blocks) |
| `README.md` | Flavour text in Italian |

## Reversing the Binary

The binary is a standard ELF compiled from `Aperitivi_Eterni_Student.c` linked against a modified `aes.c`. Running `file` on it reveals a dynamically linked, not-stripped binary — so symbol names are available, which softens the reversing burden somewhat.

The critical observation a reverser must make is in this line of the source:

```c
AES_init_ctx(&ctx, master_key, 1);
// ...
AES_encrypt(&ctx, cp1, 1);
```

The third argument is `1`. In standard AES-128 this parameter is `10` (the number of rounds). Here, both key expansion and encryption use **only 1 round**. This is the vulnerability.

### What 1-round AES looks like

Standard AES-128 applies 10 rounds of SubBytes → ShiftRows → MixColumns → AddRoundKey (with MixColumns omitted in the final round). With `r = 1`, the cipher reduces to:

$$
C = \text{AddRoundKey}_{1}\!\Big(\text{ShiftRows}\!\big(\text{SubBytes}(\text{AddRoundKey}_{0}(P))\big)\Big)
$$

That is:

1. XOR the plaintext with the master key (round key 0).
2. Apply SubBytes (the S-box, byte by byte).
3. Apply ShiftRows.
4. XOR with round key 1 (derived from the master key by one step of key expansion).

There is **no MixColumns**: meaning every output byte depends on exactly one input byte. This lack of diffusion is what makes differential cryptanalysis feasible.

## The Mathematics: Differential Cryptanalysis on 1-Round AES

This is the part I'm most proud of. The attack is a textbook application of differential cryptanalysis, but adapted to AES's specific structure.

We have two known plaintext–ciphertext pairs:

$$
(P_1, C_1) \quad \text{and} \quad (P_2, C_2)
$$

Define:

- **Input difference:** $\alpha = P_1 \oplus P_2$
- **Output difference:** $\delta = C_1 \oplus C_2$

Since 1-round AES has no MixColumns, the only non-linear component is SubBytes. The output difference $\delta$ passes through the inverse of ShiftRows to give us the difference *after* SubBytes:

$$
\beta = \text{InvShiftRows}(\delta)
$$

## The Difference Distribution Table (DDT)

The S-box $S : \{0,1\}^8 \to \{0,1\}^8$ is a fixed, public permutation. For any pair of input difference $\Delta_{\text{in}}$ and output difference $\Delta_{\text{out}}$, the DDT records which input values $(x, y)$ satisfy:

$$
x \oplus y = \Delta_{\text{in}} \quad \text{and} \quad S(x) \oplus S(y) = \Delta_{\text{out}}
$$

Construction is straightforward — iterate over all $2^{16}$ pairs $(x, y)$ where $x, y \in \{0, \ldots, 255\}$:

$$
\text{DDT}[\Delta_{\text{in}}][\Delta_{\text{out}}] = \big\{(x, y) \;\big|\; x \oplus y = \Delta_{\text{in}},\; S(x) \oplus S(y) = \Delta_{\text{out}}\big\}
$$

The AES S-box has a maximum differential probability of $4/256$, so for any non-trivial $(\Delta_{\text{in}}, \Delta_{\text{out}})$ pair, there are at most 4 solutions — meaning at most 4 candidate values per key byte.

### Recovering the Key, Byte by Byte

Because MixColumns is absent, the cipher decomposes into 16 independent byte-level problems. For byte position $i$:

- $\alpha_i = P_1[i] \oplus P_2[i]$ — known input difference
- $\beta_i$ — corresponding output difference after InvShiftRows of $\delta$

Look up $\text{DDT}[\alpha_i][\beta_i]$ to get the set of pairs $(x, y)$. Since $x = P_1[i] \oplus K_0[i]$ (where $K_0$ is the round-0 key, i.e. the master key), each pair yields a candidate:

$$
K_0[i] = x \oplus P_1[i]
$$

With at most ~4 candidates per byte, the total search space is:

$$
\prod_{i=0}^{15} |\text{candidates}_i| \;\approx\; 4^{16} = 2^{32}
$$

In practice, many positions have only 2 candidates, bringing the actual search space down to roughly $2^{16}$, trivially bruteforceable.

### Verification and Decryption

For each candidate master key $K_0$:

1. Derive the round-1 key $K_1$ via one step of AES-128 key expansion.
2. Decrypt the flag ciphertext block-by-block:
   - XOR with $K_1$ (undo final AddRoundKey)
   - InvShiftRows
   - InvSubBytes
   - XOR with $K_0$ (undo initial AddRoundKey)
3. Check whether the result contains the flag prefix `unipi{`.

### Formal Argument for Correctness

**Claim.** Given one known-plaintext differential pair under 1-round AES (no MixColumns), the master key is uniquely determined up to a small brute-force factor bounded by $4^{16}$.

**Proof sketch.** Let $K$ be the unknown key. The encryption of byte $i$ is:

$$
C'_i = S(P_i \oplus K_i)
$$

where $C'$ denotes the state before ShiftRows (we can undo ShiftRows from the ciphertext). For two plaintexts:

$$
S(P_{1,i} \oplus K_i) \oplus S(P_{2,i} \oplus K_i) = \beta_i
$$

Setting $x = P_{1,i} \oplus K_i$ and $y = P_{2,i} \oplus K_i$, we have $x \oplus y = \alpha_i$ and $S(x) \oplus S(y) = \beta_i$. The DDT gives all solutions $(x, y)$ for this system. Since the AES S-box is a permutation with differential uniformity 4 (i.e., for any non-zero $\alpha_i$, each output difference $\beta_i$ is achieved by at most 4 pairs), the number of candidates for $K_i = x \oplus P_{1,i}$ is at most 4. Over all 16 bytes, the total candidate set is at most $4^{16} = 2^{32}$, which is efficiently searchable. $\square$

The differential uniformity of the AES S-box is well-established — it was a design criterion selected by Daemen and Rijmen specifically to resist differential cryptanalysis in the full 10-round cipher. Ironically, this property also precisely characterises how *easily* the reduced cipher falls.

## Solve

> [!success]- Exploit
> ```python
>import itertools
>from math import ceil
>
># AES S-Box and inverse
>SBOX = [
> 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
> 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
> 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
> 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
> 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
> 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
> 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
> 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
> 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
> 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
> 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
> 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
> 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
> 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
> 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
> 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
>]
>
>INV_SBOX = [0]*256
>for i,v in enumerate(SBOX):
> INV_SBOX[v] = i
># utils
>
>def xor_bytes(a, b):
>
> return bytes([x ^ y for x, y in zip(a,b)])
>
>
>
>def read_bin(filename):
>
> with open(filename, "rb") as f:
>
> return f.read()
>
>
>
>def read_hex_file(filename):
>	
> 	with open(filename, "r") as f:
>	
> 	s = f.read().strip()
>	
> 	return bytes.fromhex(s)
>
>
>
># state helpers: AES uses column-major mapping: state[r][c] = bytes[c*4 + r]
>
>def inv_shiftrows(block16):
>
> 	# block16: bytes length 16
>	
> 	s = [[block16[c*4 + r] for c in range(4)] for r in range(4)]
>	
> 	# right rotate row r by r positions
>	
> 	for r in range(4):
>	
> 	if r == 0: continue
>	
> 	row = s[r]
>	
> 	rr = r % 4
>	
> 	s[r] = row[-rr:] + row[:-rr]
>	
> 	# recompose bytes
>	
> 	out = bytearray(16)
>	
> 	for r in range(4):
>	
> 		for c in range(4):
>	
> 			out[c*4 + r] = s[r][c]
>	
> 	return bytes(out)
>
>
>
># Build DDT storing (x,y) pairs for each (alpha,beta)
>
>def generate_ddt(sbox):
>
> 	ddt = [[[] for _ in range(256)] for _ in range(256)]
>	
> 	for x in range(256):
>	
> 	for y in range(256):
>	
> 	alpha = x ^ y
>	
> 	beta = sbox[x] ^ sbox[y]
>	
> 	ddt[alpha][beta].append((x,y))
>	
> 	return ddt
>	
>
>
># AES-128 key expansion (only first round key)
>
>RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]
>
>def key_expansion_128(master_key):
>
> 	# master_key: 16 bytes
>	
> 	# returns expanded round keys as list of 16-byte words (Nr+1 round keys),
>	
> 	# but we only need round 0 and round 1 (2 * 16 bytes)
>	
> 	# Implement full 176 bytes but simple approach:
>	
> 	nk = 4
>	
> 	nb = 4
>	
> 	nr = 10 # we compute full expansion but only use first two roundkeys
>	
> 	w = [0]* (4*(nr+1)) # 4-byte words count
>	
> 	# load initial key into w[0..3]
>	
> 	for i in range(nk):
>	
> 	w[i] = (master_key[4*i] << 24) | (master_key[4*i+1] << 16) | (master_key[4*i+2] << 8) | master_key[4*i+3]
>	
> 	for i in range(nk, 4*(nr+1)):
>	
> 	temp = w[i-1]
>	
> 	if i % nk == 0:
>	
> 	# RotWord
>	
> 	temp = ((temp << 8) & 0xffffffff) | ((temp >> 24) & 0xff)
>	
> 	# SubWord
>	
> 	b0 = (temp >> 24) & 0xff
>	
> 	b1 = (temp >> 16) & 0xff
>	
> 	b2 = (temp >> 8) & 0xff
>	
> 	b3 = temp & 0xff
>	
> 	sb0 = SBOX[b0]; sb1 = SBOX[b1]; sb2 = SBOX[b2]; sb3 = SBOX[b3]
>	
> 	temp = (sb0<<24) | (sb1<<16) | (sb2<<8) | sb3
>	
> 	# Rcon
>	
> 	rcon = RCON[i//nk]
>	
> 	temp ^= (rcon << 24)
>	
> 	w[i] = w[i-nk] ^ temp
>	
> 	# collect roundkeys
>	
> 	roundkeys = []
>	
> 	for r in range(nr+1):
>	
> 		rk = bytearray(16)
>		
> 		for j in range(4):
>		
> 			word = w[r*4 + j]
>			
> 			rk[4*j] = (word >> 24) & 0xff
>			
> 			rk[4*j+1] = (word >> 16) & 0xff
>			
> 			rk[4*j+2] = (word >> 8) & 0xff
>			
> 			rk[4*j+3] = word & 0xff
>		
> 		roundkeys.append(bytes(rk))
>	
> 	return roundkeys # list of 11 roundkeys (each 16 bytes)
>
>
>
># decrypt single block for 1-round AES given rk0 and rk1
>
>def decrypt_one_round_block(ct_block, rk0, rk1):
>
> 	# ct_block, rk0, rk1 are bytes 16
>	
> 	# InvAddRoundKey with rk1:
>	
> 	state = xor_bytes(ct_block, rk1)
>	
> 	# InvShiftRows
>	
> 	state = inv_shiftrows(state)
>	
> 	# InvSubBytes
>	
> 	state = bytes([INV_SBOX[b] for b in state])
>	
> 	# final AddRoundKey with rk0
>	
> 	pt = xor_bytes(state, rk0)
>	
> 	return pt
>
>
>
>def main():
>
> p1 = read_bin("p1.bin")
>
> p2 = read_bin("p2.bin")
>
> c1 = read_bin("c1.bin")
>
> c2 = read_bin("c2.bin")
>
> flag_enc = read_hex_file("flag.enc")
>
>
>
> if len(p1) < 16 or len(p2) < 16 or len(c1) < 16 or len(c2) < 16:
>
> print("Errore: aspettavo file da 16 byte: p1.bin p2.bin c1.bin c2.bin")
>
> return
>
>
>
> p1 = p1[:16]; p2 = p2[:16]; c1 = c1[:16]; c2 = c2[:16]
>
>
>
> alpha = xor_bytes(p1, p2)
>
> delta = xor_bytes(c1, c2)
>
> beta = inv_shiftrows(delta)
>
>
>
> ddt = generate_ddt(SBOX)
>
>
>
> # per ogni byte, trova i candidati rk0_byte
>
> candidates_per_byte = []
>
> for i in range(16):
>
> pairs = ddt[alpha[i]][beta[i]]
>
> cand = set()
>
> for x,y in pairs:
>
> 	cand.add(x ^ p1[i])
>	
> 	cand.add(y ^ p1[i])
>	
> 	if not cand:
>	
> 	print(f"Nessun candidato per byte {i}! alpha={alpha[i]:02x} beta={beta[i]:02x}")
>	
> 	return
>	
> candidates_per_byte.append(sorted(cand))
>
>
>
> tot = 1
>
> for lst in candidates_per_byte:
>
> 	tot *= max(1, len(lst))
>
> print(f"Totale combinazioni da provare: {tot}")
>
>
>
> # brute-force tutte le combinazioni (≈ 2^16)
>
> tried = 0
>
> for combo in itertools.product(*candidates_per_byte):
>
> tried += 1
>
> rk0 = bytes(combo) # candidate master key
>
> # expand keys to get round 1 key
>
> rks = key_expansion_128(rk0)
>
> rk1 = rks[1]
>
> # decrypt entire flag (block by block)
>
> nblocks = ceil(len(flag_enc) / 16)
>
> out = bytearray()
>
> for b in range(0, len(flag_enc), 16):
>
> ctblk = flag_enc[b:b+16]
>
> ptblk = decrypt_one_round_block(ctblk, rk0, rk1)
>
> out.extend(ptblk)
>
> # check if plausible flag
>
> try:
>
> 	s = out.decode('utf-8', errors='ignore')
>
> except:
>
> s = str(out)
>
> 	if "unipi{" in s:
>	
> 	print(" FLAG Trovata ")
>	
> 	print(s)
>	
> 	print("rk0 (master key candidate):", rk0.hex())
>	
> 	return
>
> print("Flag non trovata (nessuna combinazione valida). Provati:", tried)
>
>
>
>if __name__ == "__main__":
> main()






