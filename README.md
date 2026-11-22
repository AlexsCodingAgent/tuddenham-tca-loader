# tuddenham-tca-loader

An open reimplementation of a TCA-style application loader for UICCs and eUICCs, in Rust.

The commercial TCALoader, released by the Trusted Connectivity Alliance in September 2023 as
the successor to the SIMalliance CAT Loader, does one job: get a Java Card application onto
a card and manage it afterwards. It compiles an applet, loads it through a security domain,
installs it, and audits what the card already holds. It talks GlobalPlatform 2.3, including
SCP03 over HTTPS, and keeps SCP02, CAT-TP and SMS for older deployments.

This project is the same job in the open: inspect the card, open a secure channel, load a CAP
file, install an instance, delete what you no longer want.

## The secure channel (SCP03)

```
$ tca-loader auth                     # GlobalPlatform test keys
$ tca-loader auth --keys enc:mac:dek  # real keys, 16 bytes each in hex
$ tca-loader auth --security-level 33 # add C-DECRYPTION and response protection
```

`auth` sends INITIALIZE UPDATE, checks the card cryptogram against the static keys, derives
S-ENC, S-MAC and S-RMAC, sends EXTERNAL AUTHENTICATE, and then proves the channel by running a
MAC-wrapped GET STATUS through it.

Three things make this trustworthy without a card to test on:

- CMAC is checked against the RFC 4493 vectors
- the key derivation is checked against an independent implementation (pycryptodome, with
  GlobalPlatform's field order rather than NIST's) for the standard test keys and a fixed pair
  of challenges
- the C-MAC chains, so the same command never carries the same MAC twice

What has not happened yet: a live card. The reader here holds a USIM, which answers SELECT on
A0000001510000 with 617F and INITIALIZE UPDATE with 6E00 (class not supported), so there is no
GlobalPlatform issuer security domain to authenticate to. The next real step is a GP or eUICC
sample; until then this is verified against vectors, not against silicon.

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

- **SCP02.** Cards that predate SCP03 (and many SIMs in the field) use SCP02, which is 3DES with
  its own derivation and ICV rules. The tool speaks SCP03 only, and says so when a card reports
  SCP02 rather than pretending to authenticate.
- **DAP.** A Load File Data Block Hash can be passed, but there is no signing, no DAP block and
  no token handling, so a card that mandates verification will refuse the load.
- **Extended APDUs.** Blocks are limited to 255 bytes, which is the classic limit; cards that
  negotiate a larger block through an extended-length LOAD are not exploited.
- **eUICC specifics.** Loading to an ISD-R, profile (ISD-P) creation and deletion, and the ES10
  commands are absent. The tool works against a GlobalPlatform issuer security domain.
- **Key management.** SET STATUS and PUT KEY are not implemented, so key rotation and locking
  are still done elsewhere.

## Roadmap

1. **SCP02**, so older SIMs and cards can be loaded rather than only inspected
2. **DAP and tokens**, for security domains that mandate verification
3. **Key management**: SET STATUS, PUT KEY, extradition
4. **eUICC awareness**: ISD-R, ISD-P, ES10, so a profile is not mistaken for an application
5. **Other transports**: CAT-TP over IP, SMS, and a relay for cards behind a modem
6. **Audit**: registry walk, orphaned packages, key versions per domain

## What this is not

It is not a copy of the TCA tool, does not ship the TCA specifications, and is not certified
by anyone. It is a working reference for people who want to see how card management works, or
who need a loader they can read.

## Licence

Commercial. See `LICENSE`: the source is published for evaluation, and using it in
production, in a product or for a client needs a written licence.
