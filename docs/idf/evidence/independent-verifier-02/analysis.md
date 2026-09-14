# independent-verifier-02: rehearsal on a twin of a real EU CCMS L0 root

The same procedure as [independent-verifier-01](../independent-verifier-01/analysis.md),
this time under a root certificate that carries the exact `appPermissions`,
`certIssuePermissions` and region of a real root submitted to the EU CCMS L0
ECTL (`vidf_issue root --like <real root>.oer` with a throwaway key: the twin
differs from the real root only in key, name and validity). The real root's
public certificate itself is not part of this repository; the twin shows what
the library will do with a chain of that shape.

| File | Content |
| --- | --- |
| `TWIN_RCA.oer` | twin root: CPOC Protocol Release 3.0/3.3 permission profile (CAM 01FFFF/FF0000, DENM 02FFFFFFFF/FF00000000, TLM, RLT, IVI, TLC-R, GN-MGMT all, SCR 01C0/FF3F, TLC-S, VRU 01/FF, CP, POI; second group SCR 013E/FFC1; chain length 2, eeType app+enrol), `identifiedRegion` countryOnly 65535 (CPOC clause I.3.9) |
| `TWIN_AA.oer` | AA derived from the root by `vidf_issue authority`: the root's ranges with chain length 1, the root's region, appPermissions psid 623 ssp 0130 |
| `TWIN_AT.oer` | ticket: psid 638 (01), 141 (no SSP), 36 (01FFFC); region inherited from the AA |
| `TWIN_AT2.oer` | the same without psid 141 |
| `sut.pcap`, `sut2.pcap` | three CAM carriers each (`capture_pcap.py`; the DENM carrier is refused because the tickets carry no psid 37) |
| `c-its-standard.jsonl`, `c-its-nomgmt.jsonl` | c-its-pcap output |

## Result

| Capture | Message signature | Certificate signatures | `ee_permissions_valid` | `security_authorized` |
| --- | --- | --- | --- | --- |
| `sut2.pcap` (ticket without psid 141) | verifies (3/3) | verify (3/3) | true | **true** (3/3 CAMs) |
| `sut.pcap` (standard ticket) | verifies (3/3) | verify (3/3) | false (c-its treats the SSP-less psid 141 as unsupported, see -01) | false |

`vidf_issue` refused a ticket with the DENM SSP `01FFFFFF` under this root
(`refusing to write a ticket the issuer cannot authorise`): the root's DENM
range fixes the first octet to 02 (SSP version 2 of the CPOC 3.3 profile),
which IEEE Std 1609.2 6.4.30 makes binding for every subordinate.
`vidf_issue verify TWIN_AT.oer TWIN_AA.oer TWIN_RCA.oer` reports the three
signatures, the validity nesting, the region nesting and the permission
consistency as the library's verifier applies them.

## What this run changed in the library

The upstream region consistency (`is_within`) knows no `identifiedRegion`
issuer, so every certificate under an EU root was "inconsistent" for the
receive-side verifier. The chain validator now applies IEEE Std 1609.2 clause
6.4.17 itself: identifier containment for identified regions (whole country,
regions, subregions), the upstream geometry for geometric issuers, and the
station's `permissive_identified_region` policy for a geometric region under an
identified one (no border database on the device). `test_region_consistency`
covers the three cases (873 host checks, 747 on the ESP32-C5).
