# Conformance status

No full-stack ETSI conformity is claimed for this port. The five official BTP
cases pass against the host stack, one official GeoNetworking case
(`TC_GEONW_FDV_SHB_BV_01`, SHB source generation) passes against the host
stack, 14 of the 15 executed official Security sending-side cases pass and 24
of the 26 receiving-side cases pass (the misses are defects of the testcases,
see validation.md); this is not a complete N&T/access/security verdict. See
[interface assessment](interface-assessment.md) for the SAP contract review.
The intended deliverable is a Release 2 ITS-G5 library; the following required
work remains visible rather than being hidden behind successful compilation.

| ID | Component | Implemented boundary | Remaining acceptance work |
|---|---|---|---|
| GAP-GN-001 | GeoNetworking | Actual upstream SHB and GeoBroadcast router, forwarding state and injectable timers, plus a raw GN-DATA N-SAP (IF-GN-002) for SHB/GBC with no assumed upper-layer header; `Router::set_address` now actually applied (see docs/idf/validation.md) | GUC, GAC and TSB are upstream stubs; R2 V2.2.1 ALI/MCO architecture and other normative deltas need implementation and ATS coverage. `AtsGeoNetworking` adapter passes its one single-component SHB-source case; GBC triggering and multi-component (PTC) cases are not implemented |
| GAP-CA-001 | CA Basic Service | R2 CAM UPER codec, validation and BTP submission | Generation rules, vehicle/RSU state, special/low-frequency containers, authorization and complete CA service tests |
| GAP-DEN-001 | DEN Basic Service | R2 DENM UPER codec, validation and BTP submission | Trigger/update/terminate, action-ID tables, repetition/validity, receiving lifecycle and complete DEN service tests |
| GAP-VRU-001 | VRU Basic Service | R2 VAM UPER codec, validation and BTP submission | VAM generation and redundancy mitigation, VRU/cluster lifecycle and complete VBS service tests |
| GAP-SEC-001 | Security | `security::SecurityEntity` signs with the TS 103 097 V2.2.1 profiles from a provisioned ticket pool and trust configuration (`VIDF_SECURITY`, default on) and, with `VIDF_SECURITY_VERIFY` (default on), verifies received messages per IEEE 1609.2 clause 5.2 / TS 103 097 clause 7.1 with chain signatures to the provisioned anchors, the chain permission consistency of IEEE 1609.2 clause 5.1.2, generationTime window, replay detection and P2P certificate distribution; signed CAM/DENM confirmed by an independent verifier (c-its) against a lab chain from `vidf_issue`; PSA Crypto backend on the device (ESP32-C5 ECDSA peripheral for verification), OpenSSL on the host; identifier change (TS 102 723-8 clause 6.3) with the GN core and facilities as subscribers; official AtsSecurity sending side 14/15 and receiving side 24/26 (the misses are testcase defects) | Encryption at the SN-SAP, CTL/CRL/revocation input, identified-region (country) checks without a country database and a pseudonym change policy are absent; the 99 receiving-side CERT/GENMSG cases of TS 103 096 are not compiled in the pinned ATS and remain covered by component tests only |
| GAP-SEC-002 | Receive security metadata | Report, ITS-AID, permissions and certificate ID of the verified message reach BTP-DATA.indication (component test through the GN core; the receiving-side ATS observes the delivered payload) | The Security ATS does not check the metadata beyond delivery; a facilities-layer consumer of the SSP is the application's |
| GAP-PKI-001 | TS 102 941 client | `VIDF_PKI` (default off): EnrolmentRequest/Response and AuthorizationRequest/Response with proof of possession, ECIES/AES-CCM, request hash and `pskRecipInfo` decryption; host and PSA implementations interoperate | No HTTP/transport, CTL/CRL/ECTL retrieval, butterfly keys, re-enrolment scheduling or credential storage; no PKI ATS executed |
| GAP-ACC-001 | ITS-G5 access | EN 303 797 AL_DATA binding, external Access injection, experimental C5 adapter; independent two-board real-RF reception verified passing (`radio_pair.py`, docs/idf/validation.md) | Complete IN-SAP and required controls/measurements; DCC; this passing reception check is exact-content-match at close range, not spectral mask, frequency accuracy, sensitivity, EIRP or full ITS-G5 RF conformance |
| GAP-DCC-001 | DCC | Upstream DCC sources available in network build | Correct R2 access integration, real CBR inputs, queue/airtime behavior and verification |
| GAP-HIL-001 | TTCN/HIL | Generic upper/lower hooks, bounded optional framing; BTP, GeoNetworking and Security SUT adapters (host and, for BTP, device); the Security adapter shares one SUT process across TITAN components, so its DENM cases (triggered from a PTC) run | GeoNetworking adapter passes one single-component case (GAP-GN-001); GeoNetworking multi-component (PTC) test cases are not supported; the Security adapter covers the sending side only; CAM/DENM/VRU/IPv6oGN adapters do not exist. The GeoNetworking adapter's build also carries a documented, hash-tracked overlay working around a null-pointer bug in the external ETSI framework's own codec (`geonetworking_codec.cc`), applied only to this tool's own build output, never to the pinned checkout |

PICS must reflect these limits. Do not mark unsupported functionality as passing,
silently downgrade a transport, use dummy certificates, or acknowledge a service
action that has not happened. Component tests are maintained separately from
official ATS verdicts and adapted Release 2 verdicts.

The source tree includes legacy security envelope parsing because the upstream
router's `SecuredMessage` variant depends on it. This is an explicit dependency
gap, not a selected legacy service. Null/dummy signers, the upstream PKI tools
and experimental PQC are excluded from the IDF source list; the TS 102 941 core
of this port is a separate, optional feature (GAP-PKI-001).

An access-only deployment requires all higher-layer protocol/service behavior
to exist in its external peer. A network deployment requires complete facilities
services in its caller. The facilities profile currently adds codecs/endpoints;
full Basic Services remain part of the intended library work, not completed
features.
