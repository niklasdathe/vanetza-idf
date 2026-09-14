# independent-verifier-01: signed CAM/DENM checked by c-its

An independent implementation (c-its, Rust, https://github.com/TheEnbyperor/c-its,
commit e3bb3b82480d6df4237e2a8c35ea0dd7eade25b4 of 2026-09-07; rasn/rasn-its
codecs, RustCrypto p256) verifies what the host SUT signs with a lab credential
chain issued by `vidf_issue`. Nothing of the verification is ours: c-its
decodes the GeoNetworking and TS 103 097 structures with its own ASN.1
modules, checks the message signature, every certificate signature up to the
root it is given, the chain lengths, the end-entity permissions against the
issuers' `certIssuePermissions` and finally the CAM/DENM content against the
ticket's SSP (`security_authorized`).

## Material (public parts only)

| File | Content |
| --- | --- |
| `LAB_RCA.oer` | self-signed root, `vidf_issue root` from a throwaway P-256 key (`openssl ecparam -genkey`), CPOC-shaped `certIssuePermissions` (minChainLength 2, eeType app+enrol; second group psid 623 013E/FFC1) |
| `LAB_AA.oer` | AA under the root, appPermissions psid 623 ssp 0130 |
| `LAB_AT.oer` | standard ticket: psid 36 (01FFFC), 37 (01FFFFFF), 141 (no SSP), 638 (01) |
| `LAB_AT_NOMGMT.oer` | the same without psid 141 |
| `sut-standard.pcap`, `sut-nomgmt.pcap` | three CAM carriers (certificate, digest, certificate) and one DENM carrier (GBC) each, recorded with `tools/capture_pcap.py` |
| `c-its-standard.jsonl`, `c-its-nomgmt.jsonl` | c-its-pcap output, one JSON object per frame |

Private keys (`*.vkey`, the PEM) are not part of the evidence. The lab root is
not the project's root certificate; the procedure is the one the project root
would go through (`vidf_issue root --key <encrypted PEM>`, pass phrase prompted
by OpenSSL, never on the command line).

## Commands

```
vidf_issue root      --key lab-root.pem --name "vanetza-idf lab root" --id LAB_RCA --out chain
vidf_issue authority --issuer chain/LAB_RCA.oer --issuer-key lab-root.pem --name "vanetza-idf lab AA" --id LAB_AA --out chain
vidf_issue ticket    --issuer chain/LAB_AA.oer --issuer-key chain/LAB_AA.vkey --id LAB_AT \
                     --permission 36:01FFFC --permission 37:01FFFFFF --permission 141 --permission 638:01 --out chain
vidf_issue ticket    ... --id LAB_AT_NOMGMT --permission 36:01FFFC --permission 37:01FFFFFF --permission 638:01 --out chain
python tools/capture_pcap.py --sut vidf_sut --pool chain --root LAB_RCA --aa LAB_AA --at LAB_AT --out sut-standard.pcap
python tools/capture_pcap.py --sut vidf_sut --pool chain --root LAB_RCA --aa LAB_AA --at LAB_AT_NOMGMT --out sut-nomgmt.pcap
mkdir ctl && cp chain/LAB_RCA.oer ctl/root-LAB_RCA.oer && cp chain/LAB_AA.oer ctl/aa-LAB_AA.oer
RUST_LOG=info c-its-pcap sut-standard.pcap > c-its-standard.jsonl
RUST_LOG=info c-its-pcap sut-nomgmt.pcap   > c-its-nomgmt.jsonl
```

c-its was built on Windows with `cargo build --release --features build-binary
--bin c-its-pcap` (cargo 1.98.1). Its `ieee80211` dependency enables `defmt`
by default, which needs an embedded logger and does not link on a host; the
local checkout sets `ieee80211 = { version = "0.5.9", default-features = false,
features = ["crypto"] }` (a build change, no functional change).

## Result

| Capture | Frames | Message signature | Certificate signatures (root, AA, AT) | Chain lengths / eeType | `ee_permissions_valid` | `validated_chain` | `security_authorized` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `sut-nomgmt.pcap` | 3 CAM + 1 DENM | verifies (4/4) | verify (4/4) | root [2,2] app+enrol, AA [1,1] app | true | chain 0 (root → AA → AT) | **true** for the CAMs and the DENM |
| `sut-standard.pcap` | 3 CAM + 1 DENM | verifies (4/4) | verify (4/4) | as above | false | none | false |

The digest-signed CAM (second frame) is resolved by c-its from the certificate
it saw in the first frame; the DENM carries the certificate (TS 103 097 clause
7.1.2) and the generationLocation.

The difference between the two captures is psid 141 (GN-MGMT) alone: the
standard ticket lists it without an SSP, which IEEE Std 1609.2 permits and the
ETSI test-suite tickets do as well (`CERT_IUT_A_AT`: `<ssp aid="GN-MGMT">`
empty), and which is consistent with an issuer range `all`. c-its maps an
appPermissions entry without SSP to `AppPermission::Unsupported`
(`src/security/perms.rs`, `_ => Self::Unsupported`), and
`CertSubjectAuthorization::authorizes` returns false for every unsupported
entry (`src/security/certs.rs`), so c-its cannot validate the permissions of
any ticket that carries GN-MGMT that way. The second capture removes the
entry to show that everything else c-its checks passes.

## What this found on our side

The first attempt (not retained) used the previous lab profile: root and AA
with the default chain length (1) and a bitmap range `00/FF` for GN-MGMT, the
AA with the end-entity SSP 01C0 for psid 623. c-its verified all signatures
but reported `ee_permissions_valid: false` because a root whose
`certIssuePermissions` permit a chain of length 1 does not authorise a ticket
two certificates below it (IEEE Std 1609.2 6.4.28). The lab issuer and the
test pool now follow the EU CCMS CPOC Protocol Release 3.0 root profile
(minChainLength 2, eeType app+enrol, the two psid 623 groups) and TS 102 941
V2.2.1 Table B.6 for the CA-side SSPs; the library's own verifier gained the
chain consistency checks it lacked (`docs/idf/validation.md`, "Chain
consistency").
