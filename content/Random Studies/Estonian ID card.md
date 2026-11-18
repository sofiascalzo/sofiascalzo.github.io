
*These notes were developed during my Erasmus at the University of Tartu, Estonia.
Moving beyond the theoretical framework of the course,  by deploying budget logic analyzers, I set up a home lab  to interact with the chip's internal file system and demographics, I experimented with direct APDU command execution, turning protocol theory into hands on reverse engineering practice.*

_**Security & Privacy Note:** The ID card analyzed in this lab does not belong to me and is no longer in use. Furthermore, all sensitive personal data in the outputs has been redacted/censored for privacy reasons._

## Tags

#cryptography #smartcards #esteid  #erasmus #estonia

### Introduction: The "Computer" in a Card

Smart cards (or Integrated Circuit Cards - ICC) are miniaturized computers. Despite their modern use, their hardware specifications are comparable to systems from the late 1980s.

- **CPU:** Basic processing power, but equipped with a **Cryptographic Coprocessor** for fast modular exponentiation.
    
- **RAM:** Extremely scarce (typically **< 2 KB**).
    
- **Storage:** ~200 KB of EEPROM/Flash for the OS and persistent data.
    
- **Operating System:** Usually specialized (e.g., **JavaCard**), allowing applets to be loaded onto the chip.

### Communication Protocols & Security Layers

#### APDU (Application Protocol Data Unit)

The "language" of smart cards. Communication is strictly **half-duplex** (command-response).

** Command APDU (Header + Optional Body)**

1. **[CLA]**: Class (defines the instruction type).
    
2. **[INS]**: Instruction (e.g., `A4` for Select File, `B0` for Read Binary).
    
3. **[P1, P2]**: Parameters.
    
4. **[Lc/Data/Le]**: Length of data sent / Payload / Length expected.
    

 **Response APDU & Security Status Words**

The last two bytes (**Status Words**) are critical for debugging and security:

- `90 00`: Success.
    
- `61 XX`: (T=0 specific) Success, `XX` bytes waiting. Must send `GET RESPONSE`.
    
- `6C XX`: Wrong length; card expects exactly `XX` bytes.
    
- `63 CX`: **Security Alert**: Authentication failed. `X` attempts remaining before the chip locks.
    
- `69 82`: Security status not satisfied (e.g., PIN not entered).
    

#### T=0 vs T=1 Protocols

- **T=0**: Byte-oriented. Simpler but limited; it cannot send and receive data in the same step.
    
- **T=1**: Block-oriented. More robust, supports **Extended APDUs** (up to 64KB) and features error detection (CRC).

### The File System (ISO/IEC 7816)

The internal structure is a tree of files identified by **2-byte FIDs** (File Identifiers).

- **MF (Master File)**: The root (`3F00`).
    
- **DF (Dedicated File)**: A folder (e.g., a specific application like "Identity" or "Payment").
    
- **EF (Elementary File)**: Actual data (Certificates, Personal info).
    

**Security Implementation:** There is no `list` command. To access an EF, you must know its exact FID. Navigation is done via the `SELECT FILE` command:

- `P1=04`: Select by **AID** (Application Identifier). This is how the terminal "finds" the EstEID applet among others.

### EstEID: Estonian eID Specifics

Estonia uses the ID card as a Hardware Security Module (HSM) where private keys never leave the chip.

#### Cryptographic Identity

Modern EstEID cards use **384-bit Elliptic Curve Cryptography (ECC)**:

- **PIN1 (4 digits)**: Unlocks the **Authentication Key**. Used for logging into e-services and SSL/TLS client auth.
    
- **PIN2 (5+ digits)**: Unlocks the **Digital Signature Key**. Legally equivalent to a handwritten signature under EU law (eIDAS).
    

#### Comparison: Contact vs. Contactless (NFC)

|**Feature**|**Contact (T=1)**|**Contactless (T=CL)**|
|---|---|---|
|**Protocol**|ISO 7816|ISO 14443 (NFC)|
|**Activation**|Physical Insertion|Proximity (Answer To Select)|
|**Security**|Standard APDU|May require "Secure Messaging"|

**Note on Readers:** High-level readers can be configured via **Pseudo-APDUs**. These are commands processed by the reader itself (not the card) to control LEDs, buzzers, or timeouts.

### Threat Model

Smart cards exist to mediate mutual distrust. If all parties trusted each other, 
a USB stick would suffice.

Card holders cannot extract their own private keys intentionally. Without this, 
keys would end up on GitHub within 48 hours.

**Compromised PC**: the private key is safe (HSM), but signing can be hijacked. 
The **trusted display problem** is unsolved: malware returns an error, replaces 
the document silently, waits for the retry. Valid signature on the wrong payload.

PIN firewall readers block VERIFY APDUs from the host hence the invisible retry 
counter in the lab. They don't solve the trusted display problem.

**Forged card**: the personal data file has no cryptographic integrity guarantee. 
A Prisma kiosk reads the entire file despite needing only field 6. A programmable 
card with forged data is undetectable by the terminal.
### Physical Security & Sniffing

The connection between the card and the reader can be intercepted ("sniffed") using a **Logic Analyzer** (e.g., Saleae).

- **VCC (C1)**: Power supply.
    
- **RST (C2)**: Used to trigger the **ATR (Answer To Reset)**, which identifies the card (e.g., "SeID" for EstEID).
    
- **I/O (C7)**: Where the APDU traffic flows.
    

**Hardware Fact:** The card is powered by the reader. In contactless mode, it harvests energy from the reader's induction field to boot the CPU and execute cryptographic functions.



## [LAB] <mark style="background: #CACFD9A6;">EstEID Chip Level Reversing</mark>
### What you need

- Estonian ID Card
- OMNIKEY CardMan 1021 (Approx. EUR 15).

### Setup 
*N.B. I am using Ubuntu 24*

Simply plug the external reader into an available USB port on your host machine.

Then you must verify that the kernel has recognized the hardware. Use the following commands:

Check the kernel ring buffer for recent USB attachment events:
```Bash
$ sudo dmesg
[ 1599.744116] usb 4-2: new full-speed USB device number 3 using uhci_hcd
[ 1599.921740] usb 4-2: New USB device found, idVendor=08e6, idProduct=3437
[ 1599.921751] usb 4-2: New USB device strings: Mfr=1, Product=2, SerialNumber=0
[ 1599.921760] usb 4-2: Product: USB SmartCard Reader
[ 1599.921767] usb 4-2: Manufacturer: Gemplus
```

Verify the device appears in the list of USB buses. Notice the difference between external USB readers and built-in readers:

```Bash
$ lsusb
Bus 004 Device 003: ID 08e6:3437 Gemplus GemPC Twin SmartCard Reader  <--- external USB
Bus 005 Device 002: ID 03f0:0324 Hewlett-Packard SK-2885 keyboard
Bus 002 Device 004: ID 0b97:7762 O2 Micro Inc. Oz776 SmartCard Reader <---  built-in
```

### Software Environment Configuration

The Personal Computer/Smart Card (PC/SC) standard is implemented in Linux via the `pcscd` daemon. You must install this daemon alongside diagnostic tools.

```Bash
$ sudo apt install pcscd pcsc-tools
$ sudo /etc/init.d/pcscd start
```

Once the daemon is active, use the `pcsc_scan` utility to continuously poll the reader. This tool will display the status of the reader (e.g., whether a card is inserted or removed) and will output the card's Answer To Reset (ATR) string when a card is powered on.

```Bash
$ pcsc_scan -n
Scanning present readers...
0: O2 Micro Oz776 00 00
1: Gemalto PC Twin Reader 01 00

Reader 1: Gemalto PC Twin Reader 01 00
Card state: Card inserted,
ATR: 3B DE 18 FF C0 80 B1 FE 45 1F 03 45 73 74 45 49 44 20 76 65 72 20 31 2E 30 2B
```


With the hardware detected by the operating system, the next step is installing the middleware and libraries required to bridge the gap between the OS and your Python3 scripts.


```Bash
$ sudo apt install python3-pyscard
```

### Implementation
#### Establishing a Connection
EstEID script requires a robust connection routine that pauses execution until a card is present and identifies the specific hardware generation.
The `CardRequest` object is used to monitor the PC/SC daemon for card insertion. Once detected, the script initiates a connection via the `T=0` protocol, which is prioritized for its simplicity and broad compatibility with terminal hardware.
```python 
import sys
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.util import toHexString

# card request and wait for physical insertion 
request = CardRequest(timeout=10, cardType=AnyCardType())
card_service = request.waitforcard()
channel = card_service.connection

# connect 
channel.connect(CardConnection.T0_protocol)
print("[+] Selected reader:", channel.getReader()) [cite: 417]

# identify card generation via ATR 
atr = channel.getATR()
if atr[:11] == [0x3B, 0xDB, 0x96, 0x00, 0x80, 0xB1, 0xFE, 0x45, 0x1F, 0x83, 0x00]:
    print("[+] Estonian ID card (IDEMIA 2018)") [cite: 422]
elif atr[:11] == [0x3B, 0xDC, 0x96, 0x00, 0x80, 0xB1, 0xFE, 0x45, 0x1F, 0x83, 0x00]:
    print("[+] Estonian ID card (IDEMIA 2025 CosmoX)") [cite: 427]
elif atr[:3] == [0x3B, 0xFF, 0x96]:
    print("[+] Estonian ID card (Thales 2025)") [cite: 430]
```
#### Protocol Handling: The `send()` Wrapper

A recursive `send()` function is implemented to manage the specific behaviors of the `T=0` protocol.

- **Success (`90 00`)**: Returns the data payload directly.
    
- **Available Response (`61 XX`)**: The card indicates `XX` bytes are ready; the function automatically issues a `GET RESPONSE` (`00 C0`).
    
- **Wrong Length (`6C XX`)**: The card rejects the provided `Le` byte; the function resends the APDU with the correct length `XX`.

#### Part1: Personal Data and PIN Counters

This task involves extracting demographics from Elementary Files (EF) and querying the status of PIN attempts.

**Reading Personal Data**

The card stores identity records in a dedicated directory. The selection process differs by manufacturer:

- **IDEMIA**: Requires selecting the EstEID Applet AID (`A0...0100`), followed by navigating to Master File (MF) -> Dedicated File (DF) `5000` -> Elementary File (EF) `50XX`.
    
- **Thales**: Requires selecting the PKCS#15 AID (`A0...3135`), followed by MF -> DF `Document Data` -> EF `50XX`.
    

Records include Surname, First name, Sex, Citizenship, and the Personal ID code. Data is retrieved using the `READ BINARY` (`00 B0`) command and decoded from UTF-8.

**PIN Retry Counters**

The remaining attempts for PIN1, PIN2, and PUK are retrieved by sending an empty `VERIFY` command.

- **Context Selection**: For IDEMIA, PIN1 and PUK are checked in the MF, while PIN2 requires selecting `ADF2`. For Thales, all counters are queried from the MF.
    
- **Status Word `63 CX`**: The card returns this status word where `X` represents the remaining tries (e.g., `3 left`).

> [!abstract]- Code
>
>```python
#!/usr/bin/env python3
import sys
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
>from smartcard.util import toHexString
>
>request = CardRequest(timeout=100, cardType=AnyCardType())
card_service = request.waitforcard()
channel = card_service.connection
>
>print("[+] Selected reader:", channel.getReader())
>
>try:
>	channel.connect(CardConnection.T0_protocol)
except:
>	channel.connect(CardConnection.T1_protocol)
>
>atr = channel.getATR()
card_type = ""
>
>if atr == [0x3B,0xDB,0x96,0x00,0x80,0xB1,0xFE,0x45,0x1F,0x83,0x00,0x12,0x23,0x3F,0x53,0x65,0x49,0x44,0x0F,0x90,0x00,0xF1]:
>	print("[+] Estonian ID card (IDEMIA 2018)")
>	card_type = "idemia"
>
>elif atr == [0x3B,0xDC,0x96,0x00,0x80,0xB1,0xFE,0x45,0x1F,0x83,0x00,0x12,0x23,0x3F,0x54,0x65,0x49,0x44,0x32,0x0F,0x90,0x00,0xC3]:
>	print("[+] Estonian ID card (IDEMIA 2025 CosmoX)")
>	card_type = "idemia"
>
>elif atr == [0x3B,0xFF,0x96,0x00,0x00,0x80,0x31,0xFE,0x43,0x80,0x31,0xB8,0x53,0x65,0x49,0x44,0x64,0xB0,0x85,0x05,0x10,0x12,0x23,0x3F,0x1D]:
>
>("[+] Estonian ID card (Thales 2025)")
>
>card_type = "thales"
>else:
>	print("[-] Unknown card:", toHexString(atr))
>	sys.exit(1)
>
>def send(apdu):
>	data, sw1, sw2 = channel.transmit(apdu)
>	if [sw1,sw2] == [0x90,0x00]:
>		return data
>	elif sw1 == 0x61:
>		return send([0x00, 0xC0, 0x00, 0x00, sw2])
>	elif sw1 == 0x6C:
>		return send(apdu[0:4] + [sw2])
>	else:
>		print("Error: %02x %02x, sending APDU: %s" % (sw1, sw2, toHexString(apdu)))
>	sys.exit(1)
>
>table_idemia = {
>1:'Surname', 2:'First name', 3:'Sex', 4:'Citizenship',
>5:'Date & place of birth', 6:'Personal ID code', 7:'Document number',
>8:'Expiry date', 9:'Date & place of issuance', 10:'Type of residence permit',
>11:'Notes line 1', 12:'Notes line 2', 13:'Notes line 3', 14:'Notes line 4', 15:'Notes line 5'
>}
>
>table_thales = {
>1:'Surname', 2:'First name', 3:'Sex', 4:'Citizenship',
>5:'Date of birth', 6:'Personal ID code', 7:'Document number',
>8:'Expiry date', 9:'Date of issuance', 10:'Authority',
>11:'Place of birth', 12:'Type of residence permit 1', 13:'Type of residence permit 2',
>14:'Type of residence permit 3', 15:'Remarks front 1', 16:'Remarks front 2',
>17:'Remarks back 1', 18:'Remarks back 2', 20:'Mission 1', 21:'Mission 2',
>22:'Position 1', 23:'Position 2'
>}
>
>print("\n[+] Personal data file:")
>
>if card_type == "thales":
>	send([0x00, 0xA4, 0x04, 0x00, 0x0C, 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35])
>
>	send([0x00, 0xA4, 0x04, 0x00, 0x0D, 0x44, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x20, 0x44, 0x61, 0x74, 0x61])
>
>	active_table = table_thales
>else:	
>	send([0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00])
>	
>	send([0x00, 0xA4, 0x00, 0x0C])
>	
>	send([0x00, 0xA4, 0x01, 0x0C, 0x02, 0x50, 0x00])
>
>	active_table = table_idemia
>
>
>
>for record_id, description in active_table.items():
>	try:
>		send([0x00, 0xA4, 0x02, 0x0C, 0x02, 0x50, record_id])
>		raw_data = send([0x00, 0xB0, 0x00, 0x00, 0x00])
>		value = bytes(raw_data).decode("utf8").strip()
>		print(f"[{record_id}] {description}: {value}")
>	except Exception as e:
>		pass
>
>print("\n[+] PIN retry counters:")
>
>def get_retries(p2_param):
>	data, sw1, sw2 = channel.transmit([0x00, 0x20, 0x00, p2_param])
>	if sw1 == 0x63:
>	return sw2 & 0x0F
>	return "?"
>if card_type == "thales":
>	channel.transmit([0x00, 0xA4, 0x00, 0x0C]
>	print(f"PIN1: {get_retries(0x81)} left")
>	print(f"PIN2: {get_retries(0x82)} left")
>	print(f"PUK: {get_retries(0x83)} left")
>elif card_type == "idemia":
>	channel.transmit([0x00, 0xA4, 0x00, 0x0C])
>	print(f"PIN1: {get_retries(0x01)} left")
>	print(f"PUK: {get_retries(0x02)} left")
>	channel.transmit([0x00, 0xA4, 0x01, 0x0C, 0x02, 0xAD, 0xF2])
>	print(f"PIN2: {get_retries(0x85)} left")
>```

> [!success]- Output
> ```shell
> 
>./esteid_info.py
>[+] Selected reader: Gemalto PC Twin Reader (D46A0B5A) 00 00
[+] Estonian ID card (IDEMIA 2018)
>
>[+] Personal data file:
>[1] Surname: PIxxxYA
>[2] First name: Dxxxa
>[3] Sex: F
>[4] Citizenship: BLR
>[5] Date & place of birth: 21 07 2002 BLR
>[6] Personal ID code: 60xxxxx2
>[7] Document number: BExxxx6
>[8] Expiry date: 17 08 2023
>[9] Date & place of issuance: 04 11 2021 PPA/PBGB
>[10] Type of residence permit: ELAMISLUBA TÖÖTAMISEKS
>[11] Notes line 1: RESIDENCE PERMIT FOR EMPLOYMENT
>[12] Notes line 2: UNTIL 17 08 2023
>[13] Notes line 3: 
>[14] Notes line 4: 
>[15] Notes line 5: 
>
[+] PIN retry counters:
PIN1: 3 left
PUK:  3 left
PIN2: 1 left

#### Part2: Certificate Extraction
The goal of Task 2 is to download the Authentication and Digital Signature X.509 certificates in PEM format.
### Certificate Navigation
Certificates are stored in fixed-size files within Application Dedicated Files (ADF):

- **Authentication**: Found in `MF/ADF1/3401` (IDEMIA) or `MF/ADF1/3411` (Thales).
    
- **Signature**: Found in `MF/ADF2/341F` (IDEMIA) or `MF/ADF2/3421` (Thales).

**Dynamic Reading Strategy**

Because certificates are stored in DER (binary) form within fixed-size Elementary Files, the script must calculate the actual certificate length to avoid reading padding.

1. **Initial Read**: Read the first 10 bytes of the file.
    
2. **Length Parsing**: Parse the ASN.1 SEQUENCE length byte to determine the total certificate size.
    
3. **Looping Read**: Certificates are read in chunks using `READ BINARY`.
    
4. **Offset Management**: The `P1` and `P2` parameters of `READ BINARY` serve as a 2-byte offset (MSB and LSB).
    
5. **Output**: The binary data is saved and verified using OpenSSL commands to confirm validity against the EstEID CA chain.

> [!abstract]- Code
> ```python
>#!/usr/bin/env python3
>import sys
>import argparse
>from smartcard.System import readers
>
>parser = argparse.ArgumentParser()
>parser.add_argument('--cert', choices=['auth', 'sign'], required=True)
>parser.add_argument('--out', required=True)
>args = parser.parse_args()
>
>card_readers = readers()
>if not card_readers:
> 	sys.exit("[-] No reader found")
>
>reader = card_readers[0]
>print(f"[+] Selected reader: {reader}")
>connection = reader.createConnection()
>connection.connect()
>atr = connection.getATR()
>is_thales = (atr == [0x3B,0xFF,0x96,0x00,0x00,0x80,0x31,0xFE,0x43,0x80,0x31,0xB8,0x53,0x65,0x49,0x44,0x64,0xB0,0x85,0x05,0x10,0x12,0x23,0x3F,0x1D])
>def send(apdu):
> 	data, sw1, sw2 = connection.transmit(apdu)
> 	if [sw1, sw2] == [0x90, 0x00]:
> 		return data
> 	elif sw1 == 0x61:
> 		return send([0x00, 0xC0, 0x00, 0x00, sw2])
> 	elif sw1 == 0x6C:
> 		return send(apdu[0:4] + [sw2])
> 	else:
> 		print("Error: %02x %02x" % (sw1, sw2))
> 		sys.exit(1)
> 	
> if is_thales:
> 	print("[+] Estonian ID card (Thales 2025)")
> 	AID = [0xA0,0x00,0x00,0x00,0x63,0x50,0x4B,0x43,0x53,0x2D,0x31,0x35]
> 	send([0x00,0xA4,0x04,0x00,len(AID)] + AID)
> 	send([0x00,0xA4,0x00,0x00])
> if args.cert == 'auth':
> 	ADF = [0xAD,0xF1]
> 	EF = [0x34,0x11]
> else:
> 	ADF = [0xAD,0xF2]
> 	EF = [0x34,0x21]
> 	send([0x00,0xA4,0x01,0x0C,0x02] + ADF)
> 	send([0x00,0xA4,0x02,0x0C,0x02] + EF)
>else:
> 	print("[+] Estonian ID card (IDEMIA 2018)")
> 	AID = [0xA0,0x00,0x00,0x00,0x77,0x01,0x08,0x00,0x07,0x00,0x00,0xFE,0x00,0x00,0x01,0x00]
> 	send([0x00,0xA4,0x04,0x00,len(AID)] + AID)
> 	send([0x00,0xA4,0x00,0x0C])
> if args.cert == 'auth':
> 	ADF = [0xAD,0xF1]
> 	EF = [0x34,0x01]
> else:
> 	ADF = [0xAD,0xF2]
> 	EF = [0x34,0x1F]
> 	send([0x00,0xA4,0x01,0x0C,0x02] + ADF)
> 	send([0x00,0xA4,0x02,0x0C,0x02] + EF)
>	print(f"[=] Retrieving {args.cert} certificate...")
>	header = send([0x00,0xB0,0x00,0x00,0x0A])
>		if header[0] != 0x30:
> 			sys.exit("[-] Not a valid DER certificate")
>		if header[1] < 0x80:
> 			cert_len = header[1]
> 			header_len = 2
>		elif header[1] == 0x81:
> 			cert_len = header[2]
> 			header_len = 3
>		elif header[1] == 0x82:
> 			cert_len = (header[2] << 8) | header[3]
> 			header_len = 4
>		elif header[1] == 0x83:
> 			cert_len = (header[2] << 16) | (header[3] << 8) | header[4]
> 			header_len = 5
>		else:
> 			sys.exit("[-] Unsupported DER length encoding")
>			total_len = header_len + cert_len
>cert_data = []
>offset = 0
>while offset < total_len:
> 	remaining = total_len - offset
> 	chunk = min(remaining, 231)
> 	data = send([0x00,0xB0, offset >> 8, offset & 0xFF, chunk])
> 	cert_data.extend(data)
> 	offset += len(data)
>print(f"[+] Certificate size: {len(cert_data)} bytes")
>with open(args.out, 'wb') as f:
> 	f.write(bytes(cert_data))
>print(f"[+] Certificate stored in {args.out}")

> [!success]- Output
> ```shell
> $ python3 esteid_getcert.py --cert auth --out auth.pem
   $ python3 esteid_getcert.py --cert sign --out sign.pem
[+] Selected reader: Gemalto PC Twin Reader (D46A0B5A) 00 00
[+] Estonian ID card (IDEMIA 2018)
[=] Retrieving auth certificate...
[+] Certificate size: 1001 bytes
[+] Certificate stored in auth.pem
[+] Selected reader: Gemalto PC Twin Reader (D46A0B5A) 00 00
[+] Estonian ID card (IDEMIA 2018)
[=] Retrieving sign certificate...
[+] Certificate size: 976 bytes
[+] Certificate stored in sign.pem
 >andbox  sandbox-Aspire  …/AppliedCrypto/Lez10  venv  openssl x509 -in auth.pem -inform >der -text | grep 'Key Usage' -A 1
openssl x509 -in sign.pem -inform der -text | grep 'Key Usage' -A 1
 >           X509v3 Key Usage: critical
  >              Digital Signature, Key Agreement
  >          X509v3 Extended Key Usage: critical
   >             TLS Web Client Authentication, E-mail Protection
  >          X509v3 Key Usage: critical
  >              Non Repudiation

## Case Study: The ROCA Fallacy

> **Note:** The card used in this lab is an **IDEMIA 2018**, the final generation of the **Infineon SLE 78** platform. Its predecessor, the **Infineon JTOP 78** (widely used until 2018), belongs to the same family famously crippled by the **ROCA** vulnerability.

#### What was the ROCA Vulnerability?

**ROCA** (_Return of Coppersmith's Attack_, CVE-2017-15361) represents a landmark case in cryptographic history. It wasn't a flaw in the RSA algorithm itself, but a mistake in how Infineon’s library generated prime numbers.

- **The Flaw:** The generated RSA moduli followed a specific mathematical pattern rather than being truly random.
    
- **The Impact:** This pattern allowed attackers to factorize the public key in **polynomial time** for keys up to 2048 bits.
    
- **The Risk:** Physical access to the smart card was never required. Since a public key is, by definition, public (and easily found in the certificates you extracted during this lab), an attacker could derive the private key remotely using only computational power.

```shell
# check whether an RSA modulus is vulnerable to ROCA
pip install roca-detect
roca-detect auth.der
```

Estonia revoked ~750,000 certificates in October 2017 and temporarily suspended 
its e-voting system. It is one of the very few documented cases of mass revocation 
of national digital certificates due to a cryptographic vulnerability.


## Other Side Channel Attacks

In smart card security there are two attack categories that require no physical 
extraction of the card from the reader.

### Passive Attacks

**Power analysis**: the card has no power supply of its own,  it draws current 
from the reader. The reader can measure instantaneous consumption and infer what 
the chip is executing.

On the previous generation of the Estonian ID card (Infineon JTOP 78), power 
traces during the secure channel handshake show patterns distinguishable by eye: 
APDU parsing, modular exponentiation, padding removal. With machine learning 
applied to power traces it is possible to reconstruct the instructions being 
executed on the chip not just the macro-operations.

### Active Attacks

**Fault injection**: by introducing perturbations in clock frequency or voltage 
supply it is possible to cause controlled bit errors during execution. If a 
memory pointer is corrupted at the right moment, the card could return data 
from the wrong memory region, including private keys.

The standard vendor recommended countermeasure: **every critical condition must 
be checked twice**:

```java
// defensive pattern against single fault injection
if (authenticated) {
    if (authenticated) {  // second check: detects if the first was faulted
        performSensitiveOperation();
    }
}
```

