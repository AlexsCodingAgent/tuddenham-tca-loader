# tuddenham-tca-loader

An open reimplementation of a TCA-style application loader for UICCs and eUICCs, in Rust.

The commercial TCALoader, released by the Trusted Connectivity Alliance in September 2023 as
the successor to the SIMalliance CAT Loader, does one job: get a Java Card application onto
a card and manage it afterwards. It compiles an applet, loads it through a security domain,
installs it, and audits what the card already holds. It talks GlobalPlatform 2.3, including
SCP03 over HTTPS, and keeps SCP02, CAT-TP and SMS for older deployments.

This project is the same job in the open: inspect the card, open a secure channel, load a CAP
file, install an instance, delete what you no longer want.

## Secure channels: SCP02 and SCP03

```
$ tca-loader auth                     # GlobalPlatform test keys
$ tca-loader auth --keys enc:mac:dek  # real keys, 16 bytes each in hex
$ tca-loader auth --security-level 33 # add C-DECRYPTION and response protection
```

`auth` sends INITIALIZE UPDATE, checks the card cryptogram against the static keys, derives the
session keys, sends EXTERNAL AUTHENTICATE, and proves the channel with a MAC-wrapped GET STATUS.

The card picks the protocol and the host follows: byte 11 of the INITIALIZE UPDATE response is the
SCP identifier. **SCP03** is AES with a CMAC-based key derivation; **SCP02** is 3DES with a
sequence counter and session keys derived by encrypting a sixteen-byte constant. Which keys to
supply follows from that: 16-byte AES keys for SCP03, 16 or 24-byte 3DES keys for SCP02, and
`--scp 02` forces the 3DES reading when a 16-byte key is ambiguous.

Three things make this trustworthy without a card to test on:

- CMAC is checked against the RFC 4493 vectors
- both key derivations are checked against an independent implementation (pycryptodome) for the
  standard test keys and fixed challenges: SCP03 with GlobalPlatform's field order rather than
  NIST's, SCP02 with the 3DES constant derivation and the CBC-MAC cryptograms
- the C-MAC chains, so the same command never carries the same MAC twice
- an SCP02 mock card in the tests proves the whole path: challenge, sequence counter, cryptogram,
  EXTERNAL AUTHENTICATE, and that a secured command arrives padded to a block boundary

### What the card in the reader says

The card here is a GlobalPlatform card whose security domain is not at the classic AID, and
`probe` is how that was established rather than guessed:

```
$ tca-loader probe
ATR:    3B9F97C00A3FC6828031E073FE211F65D002331640810F07
GP issuer domain        A000000003000000  6A82 absent
GP card manager         A000000151000000  9000 present
  FCI:  A000000151000000, SCP03, max command data 255
USIM                    A0000000871002  9000 present
ISIM                    A0000000871004  9000 present

$ tca-loader keys --sd A000000151000000
KVN  INDEX TYPE     BYTES   MEANS
1    1     0x80     16      AES
2    1     0x80     16      AES
3    1     0x80     16      AES
2    64    0x82     16      3DES (3-key)
1    64    0x85     16      RSA private exponent/modulus
```

So: SCP03 with three AES-128 key set versions, a legacy 3DES set, and an RSA key for DAP. What
the card will not do is start a secure channel: INITIALIZE UPDATE answers `6882` for every key
version, which is a card-state refusal rather than a key problem, because INITIALIZE UPDATE does
not use the keys at all. A card in that state cannot be authenticated by anyone until whatever it
is waiting for happens, which is why the tool reports the status word and what it means instead
of "wrong keys".

Everything above is read without authentication, which is the point: the card discloses what it
is and which keys it wants before anyone holds them.

## Loading

```
$ tca-loader cap hello.cap                 # what the card would receive
$ tca-loader load hello.cap                # load and install, issuer domain, test keys
$ tca-loader load hello.cap --keys enc:mac:dek --privileges 2
$ tca-loader load hello.cap --no-install   # prepare the load file only
$ tca-loader delete A000000062010101 --related
```

`load` runs the three steps in the order a card demands:

1. **INSTALL [for load]** names the load file AID, the security domain, an optional hash and
   nothing else, which reserves the space
2. **LOAD** every block, P2 = block number, P1 bit 8 set on the last one, and the first block
   carrying the `C4` tag and the length of the whole file
3. **INSTALL [for install and make selectable]**, or plain install with `--not-selectable`,
   naming the load file AID, the module AID, the instance AID, the privileges and the applet's
   install parameters inside `C9`

`cap` is the dry run: it reads the JAR, checks every component's declared size against its
bytes, and prints the concatenation order the Java Card spec fixes (Header, Directory, Import,
Applet, Class, Method, StaticField, Export, ConstantPool, RefLocation, Descriptor). Getting that
order wrong is the classic way to produce a load file a card accepts and then refuses to install.

### How the write path is verified

There is no GlobalPlatform card here, so the verification is a **mock card in the test suite**:
it answers INITIALIZE UPDATE with a real card cryptogram computed from the test keys, checks the
host cryptogram in EXTERNAL AUTHENTICATE, enforces block numbering and refuses LOAD before
INSTALL. The tests then assert that the bytes it received reconstruct the CAP's load file exactly,
that only the first block is `C4`-tagged, that the last block sets the P1 last-block bit, and
that both INSTALL commands name the right AIDs. A card that answers `6985` surfaces as
"INSTALL [for load] failed: 6985", not as silence.

That is a real check of the sequence and the encoding. It is not a substitute for a card: the
things only silicon can confirm are block size negotiation, timing, and what a particular
security domain wants in its install parameters.

## Working out what a card is

```
$ tca-loader probe                      # ATR, EF_DIR, candidate AIDs, FCI and SCP parameters
$ tca-loader keys --sd <aid>            # key versions, types and lengths
$ tca-loader check --sd <aid>           # do these keys fit? no authentication attempt spent
$ tca-loader audit --sd <aid>           # registry walk over an authenticated channel
$ tca-loader dump --out card-report.txt # everything readable without keys, one file
$ tca-loader raw 8050000008000102030405060700          # one APDU
$ tca-loader raw "00A4000C023F00,00B2010426"           # several, sharing card state
```

`raw` chains APDUs because state is the whole problem with a card: an EF only reads after it has
been selected in the same session. Small refinements that make real cards work: the transport
follows `61xx` with GET RESPONSE itself, retries `6Cxx` with the length the card asked for,
reconnects once if the card drops the transaction, and cold-resets on open so a card manager that
has already seen an authentication does not answer `6882` to the next one.

## What works today

```
$ tca-loader readers
Gemalto PC Twin Reader (0F930562) 00 00	card present

$ tca-loader info
reader: Gemalto PC Twin Reader (0F930562) 00 00
issuer security domain: A000000003000000
card image number: ...
cplc: ...
  chip serial: ...
issuer identification number: ...
card recognition data: ... bytes

$ tca-loader status
AID                      STATE        PRIVILEGES
A000000003000000         PERSONALIZED 9E
```

- `probe` identifies a card whose security domain is not at the usual AID: ATR, EF_DIR
  applications, candidate AIDs with their FCI, and the SCP parameters the card advertises
- `keys` decodes the key information template: which key versions exist, of what type, how long
- `raw` sends hand-written APDUs, which is how the card above was worked out
- `readers` lists PC/SC readers and whether a card is present, with the protocol in use
- `info` selects the issuer security domain, then reads the card image number, CPLC, issuer
  identification number and card recognition data
- `status` lists security domains and applications with their GlobalPlatform life cycle and
  privileges

A card that does not answer the issuer security domain is reported as such rather than
guessed at: selecting `A000000003000000` and getting `6A82` means it is not a GlobalPlatform
card, which is the correct answer for a plain SIM.

## Layout

| Module | What it owns |
|---|---|
| `src/tlv.rs` | BER-TLV parse and encode, two byte tags, long form lengths, nested construction |
| `src/apdu.rs` | Command framing, status word decoding, "authenticate first" errors spelled out |
| `src/card.rs` | The `Transport` trait, PC/SC implementation, scripted card for tests |
| `src/gp.rs` | SELECT, GET DATA, GET STATUS, life cycle words, privilege decoding |
| `src/scp03.rs` | CMAC, GlobalPlatform key derivation, session keys, C-MAC and R-MAC |
| `src/session.rs` | INITIALIZE UPDATE, EXTERNAL AUTHENTICATE, wrapped commands, `61xx`/`6Cxx` |
| `src/cap.rs` | CAP parsing, component order, size checks, LOAD block splitting |
| `src/commands.rs` | INSTALL [for load], INSTALL [for install], DELETE payloads |
| `src/load.rs` | The load sequence and its error reporting |
| `src/main.rs` | The CLI |

The transport trait is deliberately one method wide. PC/SC is the first implementation, and
CAT-TP, SMS and a SIM-over-IP relay are meant to slot in underneath the same command layer.

## Build and test

```bash
cargo build --release
cargo test          # 35 tests, no hardware needed
```

The PC/SC path needs `pcscd` running and a reader attached. Tests never touch hardware: the
scripted transport answers APDUs from a table.

## What is not implemented yet

Stated plainly, because a loader that quietly omits a mode is worse than one that refuses:

- **DAP.** A Load File Data Block Hash can be passed, but there is no signing, no DAP block and
  no token handling, so a card that mandates verification will refuse the load.
- **Extended APDUs.** Blocks are limited to 255 bytes, which is the classic limit; cards that
  negotiate a larger block through an extended-length LOAD are not exploited.
- **eUICC specifics.** Loading to an ISD-R, profile (ISD-P) creation and deletion, and the ES10
  commands are absent. The tool works against a GlobalPlatform issuer security domain.
- **Key management.** SET STATUS and PUT KEY are not implemented, so key rotation and locking
  are still done elsewhere.

## Roadmap

1. **DAP and tokens**, for security domains that mandate verification
2. **Key management**: SET STATUS, PUT KEY, extradition
3. **eUICC awareness**: ISD-R, ISD-P, ES10, so a profile is not mistaken for an application
4. **Other transports**: CAT-TP over IP, SMS, and a relay for cards behind a modem

## What this is not

It is not a copy of the TCA tool, does not ship the TCA specifications, and is not certified
by anyone. It is a working reference for people who want to see how card management works, or
who need a loader they can read.

## Licence

Commercial. See `LICENSE`: the source is published for evaluation, and using it in
production, in a product or for a client needs a written licence.
