# Standards and interface traceability

The design baseline is ETSI Release 2. Version numbers below are explicit;
references are not a declaration that the implementation has passed conformance
testing. Comments use the local traceability IDs in this table; these IDs are
not identifiers assigned by ETSI. Primitive names and clause references identify
the actual standard contracts.

| ID | Binding/behavior | Source | Implementation |
|---|---|---|---|
| IF-IN-001 | AL_DATA.request, including R2 bandwidth, transceiver mode and datastream ID | [EN 303 797 V2.1.1](https://www.etsi.org/deliver/etsi_en/303700_303799/303797/02.01.01_60/en_303797v020101p.pdf), Annex B.2 | `access.hpp`, `access.cpp` |
| IF-IN-002 | AL_DATA.indication, CBR/RSSI/channel/receiver metadata | EN 303 797 V2.1.1, Annex B.2 | `access.hpp`, `Stack::indicate` |
| IF-NF-001 | BTP-DATA.request, conditional parameters, BTP header creation | [TS 103 836-5-1 V2.1.1](https://www.etsi.org/deliver/etsi_ts/103800_103899/1038360501/02.01.01_60/ts_1038360501v020101p.pdf), clauses 7, 8.2 and Annex A.2 | `stack.hpp`, `Stack::request` |
| IF-NF-002 | BTP-DATA.indication and header removal | TS 103 836-5-1 V2.1.1, clause 8.3 and Annex A.3 | `Stack::Impl::indicate` |
| IF-NF-ARCH | NF-SAP / GeoAware SAP placement | [TS 102 723-11 V2.0.0](https://www.etsi.org/deliver/etsi_ts/102700_102799/10272311/02.00.00_60/ts_10272311v020000p.pdf), clause 5 incorporates V1.1.1 | `nf_sap.hpp` provides the named BTP request and indication binding; remaining parameter gaps are recorded in the assessment |
| IF-GN-001 | R2 GN processing and transport/core service | [TS 103 836-4-1 V2.2.1](https://www.etsi.org/deliver/etsi_ts/103800_103899/1038360401/02.02.01_60/ts_1038360401v020201p.pdf), clauses 9/10 and Annex J | Upstream router port; **R2 changes incomplete** |
| IF-GN-002 | GN-DATA.request/.indication N-SAP: raw SDU, no assumed upper-layer header | TS 103 836-4-1 V2.2.1 clause 9.3; EN 302 636-4-1 clause 9.3 heritage | `stack.hpp`/`stack.cpp`, `Stack::request(GnRequest)`/`on_receive_gn`. SHB and GBC only, matching IF-GN-001; requires the Common Header `next_header` "Any" case, absent upstream (fixed in `vanetza/geonet/common_header.cpp`) |
| IF-G5-NET | ITS-G5 media-dependent GN/DCC-MCO behavior | [TS 103 836-4-2 V2.1.1](https://www.etsi.org/deliver/etsi_ts/103800_103899/1038360402/02.01.01_60/ts_1038360402v020101p.pdf), clauses 5–7 | Upstream GN helpers; integrated behavior pending |
| IF-FAC-001 | R2 ASN.1 message definitions | TS 103 900 V2.3.1 (CAM), TS 103 831 V2.3.1 (DENM), TS 103 300-3 V2.3.1 (VAM), TS 102 894-2 V2.4.1 (CDD) | Explicitly named R2 wrappers and selected generated ASN.1 sources |
| IF-SEC-001 | Security encapsulation/decapsulation boundary | TS 102 723-8; TS 103 097 and TS 102 941 for security profiles/trust | Injected `security::SecurityEntity`; R2 profile/provider integration pending |

Facility schemas can be traced directly to the input ASN.1 files under
`asn1/release2/` and each generated header's source notice. The source manifest
pins the upstream revision and records compiled source hashes. `facilities`
validates PDU syntax/identity; it does not claim all service-level normative
requirements are implemented.

EN 303 797 Annex B and BTP Annex A describe internal service interfaces. The
C++ representations, names, units, ownership, optional-value representation and
buffer limits are this library's bindings. The convenience API uses `data.size()`
for Length; the named NF request has an explicit `length` and rejects a mismatch
with `fl_sdu.size()`.
Omitting CBR/RSSI means a test adapter has no observation; it is a known gap if
the selected access conformance profile requires that measurement.

TS 102 723-10 specifies **IN-UNITDATA** primitives with CommandRef, DP-ID and
status. Those are distinct from the **AL_DATA** example in EN 303 797. This
library uses the latter and does not claim to implement the former by renaming
fields. BLE/USB serialization is outside either ETSI service primitive.

The R2 GN V2.2.1 edition introduces TRANSP_CORE/CORE_GAGH and MCO/ALI handling
beyond the older router's model. The interface and behavior gap must be closed
before claiming conformance to that edition. A pinned R2 facility ASN.1 codec
does not make every lower layer R2-compliant.
