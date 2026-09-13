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
| GN-DATA.request/.indication (TS 103 836-4-1 clause 9.3 N-SAP) | `Stack::request(GnRequest)`/`on_receive_gn`: raw SDU, SHB and GBC only, Common Header next_header "Any" | GUC/GAC/TSB remain Result::unsupported, matching BTP-DATA's router. No TTCN test-port adapter exists yet (GAP-HIL-001); verified so far only via a direct host-level round trip (docs/idf/validation.md), not the official AtsGeoNetworking suite. |
| SN-ENCAP / SN-DECAP (TS 102 723-8) | Injected security entity and receive metadata plumbing | Complete Release 2 security processing and the named primitive parameter binding; test certificate, permissions and report propagation. |
| MI / MN / MF | Configuration and upstream MIB objects only | Implement applicable management requests, confirmations, notifications and DCC interactions. Configuration objects are not substitutes for these SAPs. |
| SF (TS 102 723-9) | No complete implementation | Implement applicable facilities/security identity coordination. |
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
* **Security:** an unavailable root certification authority affects operational
  trust integration. It does not excuse skipping parser, cryptographic,
  permissions, rejection-path or test-fixture certificate checks. Any test trust
  domain must be isolated and identified as such.

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
Access behavior tests and independent two-radio tests remain necessary.
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
