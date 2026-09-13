# Interface and capability assessment

This is an implementation assessment, not a declaration of ETSI conformity.
The current library is a partial foundation for the requested Release 2 stack.
It cannot yet satisfy a complete ITS-G5 station's requirements by configuration.

## SAP contracts

ETSI primitive names identify behavior as well as data. A C++ convenience API
with similar fields is not automatically an implementation of that primitive.
Hyphens and dots in standard identifiers require a documented language binding;
units, presence conditions and confirmation semantics must remain explicit.

| Contract | Current implementation | Required work |
|---|---|---|
| IN-UNITDATA.request (TS 102 723-10, 5.2) | AL_DATA radio request carries addresses, payload and radio controls | Add CommandRef, optional Protocol, DP-ID and TxParameters with ServiceClass, UseRTS, TxPower in 0.5 dBm units and MCS. Implement DCC profile selection rather than equating DP-ID to priority. |
| IN-UNITDATA.indication (5.3) | Receive path carries addresses, payload, channel and optional RSSI | Supply Protocol and mandatory RxParameters, including actual received MCS. Missing observations must not be invented. |
| IN-UNITDATA.status (5.4) | Driver submission result only | Correlate CommandRef and report actual addresses, channel, TxStatus and TxParameters. Successful submission is not proof of completed transmission. |
| AL_DATA (EN 303 797 Annex B) | Technology-specific request/indication binding and experimental C5 adapter | Validate driver behavior and document unsupported controls; this boundary does not replace IN-UNITDATA. |
| BTP-DATA.request (TS 103 836-5-1 Annex A.2; TS 102 723-11 R2) | NF_SAP::BTP_DATA_request submits real BTP-A/B through the upstream router | The binding exposes fl_sdu, btp_type, destination_port, destination_port_info, gn_packet_transport_type, gn_communication_profile, gn_security_profile, gn_traffic_class, gn_maximum_packet_lifetime and length. Retain the general BTP-A and geographic parameters required by the BTP specification. The binding checks length against the owned payload and rejects security-policy mismatches. Lifetime currently uses the GN encoded type; the extracted millisecond binding remains to be reconciled. |
| BTP-DATA.indication (Annex A.3) | BtpIndication includes payload, ports and GN metadata | Publish the full indication contract; a use-case extraction containing only received_fl_sdu is not the complete general BTP primitive. |
| GN-DATA.request/.indication (TS 103 836-4-1 clause 9.3 N-SAP) | `Stack::request(GnRequest)`/`on_receive_gn`: raw SDU, SHB and GBC only, Common Header next_header "Any" | GUC/GAC/TSB remain Result::unsupported, matching BTP-DATA's router. The GeoNetworking adapter exercises SHB only (one official case, docs/idf/validation.md); GBC is exercised by the Security campaign's DENM carrier, not by AtsGeoNetworking. |
| GN address configuration (TS 103 836-4-1 clauses 10.2.1.2 to 10.2.1.4) | AUTO from the MIB, MANAGED through `Stack::set_address`/`CORE_MMT_response_apply`, ANONYMOUS by subscribing the GN core to the security entity's identifier change (MID from the ticket's HashedId8, locally administered bit set) | Duplicate address detection and the R2 ALI/MCO address handling remain upstream gaps (GAP-GN-001). |
| SN-ENCAP / SN-DECAP (TS 102 723-8 Tables 22 to 27) | `sn_sap.hpp` binds both primitives; `security::SecurityEntity` signs with the TS 103 097 V2.2.1 profiles (CAM, DENM, generic, VAM individual/cluster through `context_information`), a provisioned ticket pool and a trust configuration; refuses without a valid ticket, permission or anchored chain; SN-DECAP returns the report of the missing verification, never `Success` | Verification of received messages (certificate chain, signature, permissions, replay/time/location plausibility) and the P2P certificate distribution are not implemented (GAP-SEC-001); `VIDF_SECURITY_VERIFY` fails the build rather than pretending. Encrypted messages (SN-ENCRYPT/-DECRYPT) are not bound. |
| SN-IDCHANGE-* / SN-ID-LOCK (TS 102 723-8 clauses 5.2.5 to 5.2.10, 6.3) | `security::IdentityManager`: subscription with subscriber data, PREPARE/COMMIT/ABORT/DEREG two-phase commit with a response timeout, lock 0..255 s with expiry, trigger; the GN core is a subscriber; every layer holding an identifier derives it from the HashedId8 (TS 102 940 clause 6.5) | Pseudonym change policy (when to change, TS 102 941 clause 6.3 / TS 103 097 profile timing) is the application's; the library changes on trigger and after a lock expires. No station-wide policy engine. |
| SF-IDCHANGE-* / SF-ID-LOCK (TS 102 723-9 Tables 10 to 21) | `sf_sap.hpp` exposes the same `IdChangeService` to the facilities layer (clause 4.1.5); the VRU basic service subscriber behaviour of TS 103 300-3 clause 5.3.5 is bound and component-tested | SF-SIGN/-VERIFY/-ENCRYPT/-DECRYPT/-ENCAP/-DECAP exist as parameter types only: facilities messages over BTP are secured in the GN core, and a facilities-level security service is not implemented. |
| MN (TS 102 723-4; TS 103 836-4-1 Annex K; TS 103 175 clause 8.3) | `mn_sap.hpp`: CORE_MMT.request/.response applied to the stack (time, position vector, GN address, TC mapping), MN-GET/MN-SET of the DCC N-Params through a `NetworkParameterProvider`, MN-COMMAND/-REQUEST envelope with ErrStatus 5 for an undefined number | DCC N-Param values come only from the application's provider (ErrStatus 250 when none); the management entity itself, notifications and the DCC cross-layer algorithm are not part of the library. |
| MF (TS 102 723-5; TS 103 175 clause 8.4) | `mf_sap.hpp`: MF-SET of the F-Params (channel number, available resource) into a `FacilitiesParameterSink`, MF-COMMAND/-REQUEST with ErrStatus 5 | The facilities layer that reacts to the available resource is the application's (GAP-CA/DEN/VRU-001). |
| MI (TS 102 723-3 clauses 7/8; TS 103 175 clause 8.2) | `mi_sap.hpp`: MI-SET/MI-GET of the DCC I-Params 52 to 57 with MAC-ID and CommandRef through an `AccessParameterProvider` | Channel load, transmit timing and power limits are measured or applied by the access adapter only; no value is invented (GAP-ACC-001, GAP-DCC-001). |
| FA / MA / SA | Application-facing APIs | Document service-specific interfaces; do not invent a universal ETSI primitive set. |

The R2 wrappers TS 102 723-5, -8 and -11 V2.0.0 incorporate their V1.1.1
provisions. Edition and incorporated clause references must be retained together.

## Capability verdict

* **Modularity:** explicit access and transport entry points, owned buffers and
  injected time/security are suitable foundations for multiple deployments.
* **Facilities:** CAM, DENM and VAM codecs exist. Full CA, DEN and VRU Basic Service
  generation, lifecycle and receiving behavior are still missing.
* **Networking:** SHB and GeoBroadcast use the actual upstream router, reachable
  either through the BTP-DATA N-SAP binding or directly through the raw
  GN-DATA N-SAP (IF-GN-002) for a non-BTP SDU. Other transport modes and
  Release 2 deltas remain incomplete.
* **Access:** the integrated C5 implementation is experimental. DCC, trustworthy
  channel measurements and completed-transmission reporting remain acceptance gaps.
* **Portability:** host tests do not establish support for every ESP32 target.
  Each selected component profile needs a target build and resource assessment.
* **Security:** signing, ticket selection, trust anchoring and the identifier
  change are implemented and tested on the host (OpenSSL and PSA) and on the
  ESP32-C5 (PSA Crypto of mbedTLS 4.1); the official AtsSecurity sending-side
  cases pass with the framework verifying every signature (validation.md).
  Verification of received messages is absent and the build refuses to
  pretend otherwise. The TS 102 941 enrolment/authorization core builds and
  parses the messages; it has no transport, CTL/CRL handling or scheduling.
  The test trust domain (`vidf_test_pool`, `TrustDomain`) is generated per run,
  isolated and named as such; the thesis project's root CA key is never used
  by this library.

## Test interpretation

The five official BTP cases pass against both the host stack and the real
ESP32-C5 device SUT over USB. This covers BTP only, not a full Networking &
Transport plus Access campaign. The GeoNetworking ATS now has a working
adapter: its one single-component SHB-source case
(`TC_GEONW_FDV_SHB_BV_01`) passes against the host stack, after fixing a real
null-pointer bug in the external framework's own codec and a real bug in
`Stack` (the router's configured local GN address was never actually applied
to outgoing packets — see docs/idf/validation.md for both). The other two
cases are legitimate non-passes, not bugs: one INCONC from its own PICS gate
disabling it first, one FAIL from an unimplemented multi-component (PTC) gap.
The AtsSecurity sending-side campaigns (15 official cases, two stimulus
configurations) pass except `TC_SEC_ITSS_SND_GENMSG_05_BV`, whose failing
branch is an IUT-independent unit defect of the testcase itself; see
[security-host-01/analysis.md](evidence/security-host-01/analysis.md). The
receiving-side cases were not executed because SN-DECAP verification does
not exist. Access behavior tests and independent two-radio tests remain
necessary.
Physical-layer conformance requires appropriate measurement equipment;
reception by a second C5 alone cannot establish it.

The separately installed ETSI framework remains external to this repository.
`run_etsi.py` requires an `--expected-cases` JSON list and retains missing,
unexpected and duplicate case names. A process exit code or partial collection
of PASS verdicts cannot establish a complete passing campaign. Use the supplied
`ports/esp_idf/tests/etsi_btp_cases.json` for the five-case BTP control.

## Allocation reference

VAM's destination port is **2018**, not 2009 (which belongs to CPM), per
[TS 103 248 V2.4.1 Table 1](https://www.etsi.org/deliver/etsi_ts/103200_103299/103248/02.04.01_60/ts_103248v020401p.pdf).
