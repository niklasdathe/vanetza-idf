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
| GAP-CA-001 | CA Basic Service | R2 CAM UPER codec, validation and BTP submission | Generation rules, vehicle/RSU state, special/low-frequency containers, authorization and complete CA service tests. Decided 2026-09-21: not pursued inside this library for the micrOBU thesis project — CAM/VAM generation for that project lives on the phone (`microbuapp`) under DEC-VBS-003's NF-SAP split, which this library only carries as BTP-DATA payloads. Remains a library-level future-work item (ACT-020/ACT-028), not a thesis deliverable |
| GAP-DEN-001 | DEN Basic Service | R2 DENM UPER codec, validation and BTP submission | Trigger/update/terminate, action-ID tables, repetition/validity, receiving lifecycle and complete DEN service tests. Not needed by the micrOBU thesis project (see GAP-CA-001); DEN basic service was never decided as library scope either (ACT-020) |
| GAP-VRU-001 | VRU Basic Service | R2 VAM UPER codec, validation and BTP submission | VAM generation and redundancy mitigation, VRU/cluster lifecycle and complete VBS service tests. Decided 2026-09-21: not pursued inside this library for the micrOBU thesis project, for the same reason as GAP-CA-001 (VBS lives on the phone) |
| GAP-SEC-001 | Security | `security::SecurityEntity` signs with the TS 103 097 V2.2.1 profiles from a provisioned ticket pool and trust configuration (`VIDF_SECURITY`, default on) and, with `VIDF_SECURITY_VERIFY` (default on), verifies received messages per IEEE 1609.2 clause 5.2 / TS 103 097 clause 7.1 with chain signatures to the provisioned anchors, the chain permission consistency of IEEE 1609.2 clause 5.1.2, generationTime window, replay detection and P2P certificate distribution; signed CAM/DENM confirmed by an independent verifier (c-its) against a lab chain from `vidf_issue`; PSA Crypto backend on the device (ESP32-C5 ECDSA peripheral for verification), OpenSSL on the host; identifier change (TS 102 723-8 clause 6.3) with the GN core and facilities as subscribers; official AtsSecurity sending side 14/15 and receiving side 24/26 (the misses are testcase defects) | Encryption at the SN-SAP, identified-region (country) borders (a border database) and a pseudonym change policy are absent; revocation input exists (TS 102 941 CRL through `pki::apply`); 61 of the 102 active AtsSecurity cases are not run (ATS coverage table below); the 99 receiving-side CERT/GENMSG cases of TS 103 096 are not compiled in the pinned ATS and remain covered by component tests only |
| GAP-SEC-002 | Receive security metadata | Report, ITS-AID, permissions and certificate ID of the verified message reach BTP-DATA.indication (component test through the GN core; the receiving-side ATS observes the delivered payload) | The Security ATS does not check the metadata beyond delivery; a facilities-layer consumer of the SSP is the application's |
| GAP-PKI-001 | TS 102 941 client | `VIDF_PKI` (default off): EnrolmentRequest/Response and AuthorizationRequest/Response with proof of possession, ECIES/AES-CCM, request hash and `pskRecipInfo` decryption; host and PSA implementations interoperate | No HTTP/transport (the DC GETs of Annex D are the test tools' `fetch_trust_lists.py`), no ECTL/TLM handling, no butterfly keys or re-enrolment scheduling; no PKI ATS executed (credential storage exists: `credentials.hpp`, file and NVS stores; RCA CTL/CRL building, verification and application exist: `pki::build_rca_ctl`, `parse_rca_ctl`, `parse_crl`, `apply`, evidence trust-lists-01) |
| GAP-ACC-001 | ITS-G5 access | EN 303 797 AL_DATA binding, external Access injection, experimental C5 adapter; independent two-board real-RF reception verified passing (`radio_pair.py`, docs/idf/validation.md); carrier-frequency-offset and spectral-mask measurements against EN 302 571 V2.1.1 clause 4.2.1/Table 6 now exist (2026-09-21, `experiments/evidence/c5-radio-characterization` in the thesis workspace, HackRF One/PortaPack, 3 bench configurations x 4 channels x 8 MCS rates) | Complete IN-SAP and required controls/measurements; DCC; the reception check remains exact-content-match at close range, not full ITS-G5 RF conformance. The new RF campaign found CFO generally within the +-20 ppm limit but the spectral mask failing Table 6 in every configuration and MCS rate tested (0/22 captures per run) — labelled experimental per SYS-RF-001, calibrated cable/fixture loss, an in-range control channel and a temperature sweep are still outstanding before this can support a conformance claim either way; receiver sensitivity and EIRP remain unmeasured |
| GAP-DCC-001 | DCC | 2026-09-21: DCC_ACC (`vanetza_idf::AccessStack::enable_dcc`, TS 102 687 V1.2.1 clause 5.4 Adaptive approach via the upstream `Limeric`/`LimericBudget`, CBR_target overridden to the Release-2 value 0.62) and DCC_NET (`vanetza_idf::Stack` now instantiates `geonet::DccInformationSharing`/`CbrAggregator` and calls `Router::set_dcc_field_generator`, replacing the default `NullDccFieldGenerator`) are wired in and fed from the real ESP32-C5 hardware LCBR (`C5Radio::read_cca_counters`); host tests (`test_dcc.cpp`, `test_dcc_net.cpp`) pass on all three host configurations (network+security, network-only, access-only unaffected since the DCC methods are `VIDF_NETWORK`-gated), and the full ESP32-C5 firmware builds against it | Not yet run on the device: on-hardware duty-cycle observation and the still-open BLE-coexistence comparison (ACT-021/ACT-033); DccInformationSharing is constructed unconditionally with the Stack rather than gated on "a valid LCBR source available" (SYS-DCC-003 acceptance criterion 1); queue-based airtime/backpressure behavior beyond a single-slot accept/reject gate is out of scope |
| GAP-HIL-001 | TTCN/HIL | Generic upper/lower hooks, bounded optional framing; BTP, GeoNetworking and Security SUT adapters (host and, for BTP, device); the Security adapter shares one SUT process across TITAN components, so its DENM cases (triggered from a PTC) run | GeoNetworking adapter passes one single-component case (GAP-GN-001); GeoNetworking multi-component (PTC) test cases are not supported; the Security adapter's device execution provisions the SUT through diagnostic command 9 (`serial_sut.py --bundle`) and was run for the capture path, not yet for the AtsSecurity campaigns; CAM/DENM/VRU/IPv6oGN adapters do not exist. The GeoNetworking adapter's build also carries a documented, hash-tracked overlay working around a null-pointer bug in the external ETSI framework's own codec (`geonetworking_codec.cc`), applied only to this tool's own build output, never to the pinned checkout |

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

## Official ATS coverage (pinned TS.ITS framework, audit of 2026-09-14)

Which of the ETSI TTCN-3 suites the library is meant to face, and how much of
each it actually faces today. "Active" counts `testcase` declarations compiled
in the pinned suite; the Security suite additionally carries 99 commented-out
receiving-side cases. Counts from `docs/idf/evidence` and the suites themselves.

| ATS | Active cases | Run by this library | Verdicts | Not run: why |
|---|---|---|---|---|
| AtsBTP | 5 | 5 (host, device) | 5 pass | — |
| AtsGeoNetworking | 152 | 3 | 1 pass, 1 inconc, 1 fail | The adapter drives one component; 149 cases need the multi-component (PTC) test configuration and GUC/GAC/TSB/forwarding behaviour (GAP-GN-001, thesis ACT-018) |
| AtsSecurity | 102 (+99 commented out) | 41 (8 GN-MGMT, 7 CAM/DENM sending, 26 receiving) | 39 pass, 1 fail and 2 errors on testcase defects | 54 sending-side and 7 receiving-side cases: 18 need Brainpool or implicit certificates (outside the PICS), the other 43 need the IUT to sign with other certificates per case (`CERT_IUT_A1..A4`, `_C*`, `_D`, `_E`, `_AT_8`: expired/future/region-restricted/permission-limited tickets, foreign AAs for P2P) which the pool generator does not produce and the adapter cannot select at run time (`AcEnableSecurity` maps to one pool). Thesis ACT-029 |
| AtsPki | 163 | 0 | — | The TS 102 941 core builds/parses the messages but the ITS-S side of the suite needs an HTTP client harness driven by the upper tester (enrolment/authorization towards the test system's EA/AA); GAP-PKI-001 |
| AtsCAM | 76 | 0 | — | No CA basic service in the library (GAP-CA-001; decision 2026-09-21: not pursued for the thesis project, CAM generation lives on the phone) |
| AtsVRU | 72 | 0 | — | No VRU basic service in the library (GAP-VRU-001; decision 2026-09-21: not pursued for the thesis project, VBS lives on the phone; 69 of the 72 cases also require `PICS_IS_IUT_SECURED`, which the security entity now supports) |
| AtsDENM | 135 | 0 | — | No DEN basic service (GAP-DEN-001); not decided |
| AtsCPS, AtsIS, AtsMBR, AtsIPv6OverGeoNetworking | 21, 205, 25, 21 | 0 | — | CPM, IVI/MAP/SPAT/SREM/SSEM, MCO and IPv6-over-GN are outside this library's profile |

