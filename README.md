# tuddenham-tca-loader

An open reimplementation of a TCA-style application loader for UICCs and eUICCs, in Rust.

The commercial TCALoader, released by the Trusted Connectivity Alliance in September 2023 as
the successor to the SIMalliance CAT Loader, does one job: get a Java Card application onto
a card and manage it afterwards. It compiles an applet, loads it through a security domain,
installs it, and audits what the card already holds. It talks GlobalPlatform 2.3, including
SCP03 over HTTPS, and keeps SCP02, CAT-TP and SMS for older deployments.

This project is the same job in the open. Right now it does the read half, which is the part
that has to be right before anything writes to a card.

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
| `src/main.rs` | The CLI |

The transport trait is deliberately one method wide. PC/SC is the first implementation, and
CAT-TP, SMS and a SIM-over-IP relay are meant to slot in underneath the same command layer.

## Build and test

```bash
cargo build --release
cargo test          # 14 tests, no hardware needed
```

The PC/SC path needs `pcscd` running and a reader attached. Tests never touch hardware: the
scripted transport answers APDUs from a table.

## Roadmap

1. **Secure channel**: SCP02 and SCP03, key derivation, C-MAC and encryption, so commands can
   reach a card that requires authentication
2. **Loading**: CAP file parsing, DAP verification, LOAD blocks of 255 bytes, INSTALL [for
   load] and [for install] with install parameters
3. **Management**: DELETE with token, SET STATUS, PUT KEY for key rotation, extradition
4. **Audit**: full registry walk, orphaned packages, key versions, security domain privileges
5. **Other transports**: CAT-TP over IP, SMS, and a relay for cards behind a modem
6. **eUICC awareness**: ISD-R and ISD-P handling, so the tool does not confuse a profile
   security domain with an application

## What this is not

It is not a copy of the TCA tool, does not ship the TCA specifications, and is not certified
by anyone. It is a working reference for people who want to see how card management works, or
who need a loader they can read.

## Licence

MIT.
