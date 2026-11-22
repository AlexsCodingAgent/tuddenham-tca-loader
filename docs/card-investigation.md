# The card in the reader: what it is, and why it will not authenticate

Everything below was read from the card with `tca-loader probe`, `keys` and `raw`, without any
static keys. The raw APDU is given for each claim so it can be repeated.

## Identity

| Fact | Value | How |
|---|---|---|
| ATR | `3B9F97C00A3FC6828031E073FE211F65D002331640810F07` | PC/SC status |
| Protocol | T=0, and T=15 declared | ATR decode (pcsc_scan) |
| Card type | SIM-shaped UICC, 3G and 1.8 V classes | ATR TA(3) |
| Applications | USIM `A0000000871002`, ISIM `A0000000871004`, PKCS#15 `A000000063504B43532D3135` | EF_DIR records |
| ICCID | raw `981088024147738680F2`, nibble-swapped `8901882014743768082F` (the trailing `F` is field padding) | select `3F00`/`2FE2`, READ BINARY |
| Card model string | `GTO04M01` | FCI card data, tag `66` |
| GlobalPlatform domain | `A000000151000000` (not the classic `A000000003000000`, which answers 6A82) | SELECT by AID |
| CPLC | `1290 00D3 0077 6031 0109 AE68 FF37006B 000E` | GET DATA `9F7F` |

The FCI of `A000000151000000` carries the GlobalPlatform card recognition OIDs, including the
secure channel protocol, and `9F65 01 FF` (max command data 255). It does not carry the GP 2.2
`80`/`81` entries, so this card manager speaks the older FCI layout.

## Key sets, read without keys

`GET DATA 00E0` answers on this card even unauthenticated:

| KVN | Key index | Type | Length | Meaning |
|---|---|---|---|---|
| 1 | 1 | `0x80` | 16 | AES |
| 2 | 1 | `0x80` | 16 | AES |
| 3 | 1 | `0x80` | 16 | AES |
| 2 | 64 | `0x82` | 16 | 3DES, 3-key |
| 1 | 64 | `0x85` | 16 | RSA private exponent |

So three AES-128 key set versions for SCP03, one legacy 3DES set, and an RSA key for DAP
verification. That is a precise shopping list for the card issuer, and it is available with no
credentials at all.

## The refusal

`INITIALIZE UPDATE` (`80 50 00 00 08 <8 bytes> 00`) answers **6882** in every variant tried:

- key version P1 = 00, 01, 02, 03, 40, 7F, FF
- with Le, without Le, and with Le 08, 1C, 20
- CLA 0x80 and CLA 0x84 and CLA 0x00
- plain and extended-length APDU
- immediately after SELECT, after a double INITIALIZE UPDATE, and after MANAGE CHANNEL
- on logical channel 1: 6881 (no logical channels)
- on the USIM/ISIM applets: 6E00 (class not supported there)

6882 is a state or policy refusal, and the important part is that **INITIALIZE UPDATE does not use
the static keys**: the host challenge is arbitrary and the card derives its cryptogram from its own
keys. A card that wanted different keys would still answer with a challenge, and the mismatch
would only appear afterwards, at the card cryptogram check. So this is not "the keys are wrong".

Other state probes agree that the domain is closed rather than merely unauthenticated:

- `GET STATUS` (both `80 F2 80 00 02 4F 00` and `80 F2 40 00 02 4F 00`) answer **6985**,
  conditions of use not satisfied
- `GET DATA 00C0` (extended card resources) and `00C2` answer **6A88**, not found
- `GET DATA 0066` (card recognition), `0067` (card capabilities), `00E0` (keys) and `9F7F` (CPLC)
  all answer normally

## What that means

A GlobalPlatform card manager that discloses its keys and capabilities but refuses to begin a secure
channel is one that has been **terminated or disabled by its issuer**. On commercial SIMs this is the
normal end state: once the operator has personalised the card and loaded what it wants, the card
manager is closed so that nobody else can load an applet onto it.

Nothing in the tool can change that, and neither could the correct keys: a terminated security
domain refuses INITIALIZE UPDATE from everyone.

To exercise the write path on silicon, the card needs to be a deployable UICC or eUICC with a live
issuer security domain, which in practice means a development card from a vendor (with its key
set), not a production SIM out of a phone.

## Reproducing it

```
tca-loader probe
tca-loader keys --sd A000000151000000
tca-loader raw "00A4040008A00000015100000000,8050000008000102030405060700"
tca-loader raw "00A4040008A00000015100000000,80CA00E020"
tca-loader raw "00A4000C023F00,00A4000C022F00,00B2010426,00B2020426,00B2030426"
tca-loader raw "00A4000C023F00,00A4000C022FE2,00B000000A"
```
