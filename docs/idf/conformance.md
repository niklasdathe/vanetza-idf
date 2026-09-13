# Conformance status

No full-stack ETSI conformity is claimed for this port. The five official BTP
cases pass against the host stack, and one official GeoNetworking case
(`TC_GEONW_FDV_SHB_BV_01`, SHB source generation) passes against the host
stack; this is not a complete N&T/access verdict. See
[interface assessment](interface-assessment.md) for the SAP contract review.
The intended deliverable is a Release 2 ITS-G5 library; the following required
work remains visible rather than being hidden behind successful compilation.

| ID | Component | Implemented boundary | Remaining acceptance work |
|---|---|---|---|
| GAP-GN-001 | GeoNetworking | Actual upstream SHB and GeoBroadcast router, forwarding state and injectable timers, plus a raw GN-DATA N-SAP (IF-GN-002) for SHB/GBC with no assumed upper-layer header; `Router::set_address` now actually applied (see docs/idf/validation.md) | GUC, GAC and TSB are upstream stubs; R2 V2.2.1 ALI/MCO architecture and other normative deltas need implementation and ATS coverage. `AtsGeoNetworking` adapter passes its one single-component SHB-source case; GBC triggering and multi-component (PTC) cases are not implemented |
| GAP-CA-001 | CA Basic Service | R2 CAM UPER codec, validation and BTP submission | Generation rules, vehicle/RSU state, special/low-frequency containers, authorization and complete CA service tests |
| GAP-DEN-001 | DEN Basic Service | R2 DENM UPER codec, validation and BTP submission | Trigger/update/terminate, action-ID tables, repetition/validity, receiving lifecycle and complete DEN service tests |
| GAP-VRU-001 | VRU Basic Service | R2 VAM UPER codec, validation and BTP submission | VAM generation and redundancy mitigation, VRU/cluster lifecycle and complete VBS service tests |
| GAP-SEC-001 | Security | Injectable security entity; missing signer fails closed | R2 ASN.1/profile migration, production crypto backend, credential/trust/pseudonym integration, security ATS |
| GAP-SEC-002 | Receive security metadata | Report/ITS-AID/permissions and optional certificate ID forwarded | Security ATS must verify the complete metadata path |
| GAP-ACC-001 | ITS-G5 access | EN 303 797 AL_DATA binding, external Access injection, experimental C5 adapter; independent two-board real-RF reception verified passing (`radio_pair.py`, docs/idf/validation.md) | Complete IN-SAP and required controls/measurements; DCC; this passing reception check is exact-content-match at close range, not spectral mask, frequency accuracy, sensitivity, EIRP or full ITS-G5 RF conformance |
| GAP-DCC-001 | DCC | Upstream DCC sources available in network build | Correct R2 access integration, real CBR inputs, queue/airtime behavior and verification |
| GAP-HIL-001 | TTCN/HIL | Generic upper/lower hooks, bounded optional framing; BTP and GeoNetworking SUT adapters (host and, for BTP, device) | GeoNetworking adapter passes one single-component case (GAP-GN-001); multi-component (PTC) test cases are not supported by either adapter; CAM/DENM/VRU/Security/IPv6oGN adapters do not exist. The GeoNetworking adapter's build also carries a documented, hash-tracked overlay working around a null-pointer bug in the external ETSI framework's own codec (`geonetworking_codec.cc`), applied only to this tool's own build output, never to the pinned checkout |

PICS must reflect these limits. Do not mark unsupported functionality as passing,
silently downgrade a transport, use dummy certificates, or acknowledge a service
action that has not happened. Component tests are maintained separately from
official ATS verdicts and adapted Release 2 verdicts.

The source tree includes legacy security envelope parsing because the upstream
router's `SecuredMessage` variant depends on it. This is an explicit dependency
gap, not a selected legacy service or claim of R2 security support. Null/dummy
signers, PKI clients and experimental PQC are excluded from the IDF source list.

An access-only deployment requires all higher-layer protocol/service behavior
to exist in its external peer. A network deployment requires complete facilities
services in its caller. The facilities profile currently adds codecs/endpoints;
full Basic Services remain part of the intended library work, not completed
features.
