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
| IF-GN-003 | GN address configuration: AUTO, MANAGED (CORE_MMT) and ANONYMOUS (MID from the security entity's identifier), MID rewrite on identifier change | TS 103 836-4-1 V2.2.1 clauses 10.2.1.2 to 10.2.1.4, Annex J.2 (security context information), Annex K (CORE_MMT) | `Stack::Impl` subscribes to the identifier change when `itsGnLocalAddrConfMethod` is ANONYMOUS; `Stack::set_address` for MANAGED; `mn_sap.hpp` `CORE_MMT_response_apply` |
| IF-SN-001 | SN-ENCAP.request/.confirm, SN-DECAP.request/.confirm with ITS-AID, permissions, context information and the report codes of Table 27 (SUCCESS only after verification) | [TS 102 723-8 V2.0.0](https://www.etsi.org/deliver/etsi_ts/102700_102799/10272308/02.00.00_60/ts_10272308v020000p.pdf) clause 5 incorporates V1.1.1 Tables 10 to 27 | `sn_sap.hpp` (`SN_ENCAP_request_submit`, `SN_DECAP_request_submit`), `security::SecurityEntity`; the router calls the same entity (`Router::encap_packet` with the additive `context_information` plumbing) |
| IF-SN-002 | SN-IDCHANGE-SUBSCRIBE/-EVENT/-UNSUBSCRIBE/-TRIGGER, SN-ID-LOCK/-UNLOCK; two-phase commit PREPARE/COMMIT/ABORT/DEREG, lock 0..255 s, response timeout | TS 102 723-8 V1.1.1 clauses 5.2.5 to 5.2.10 and 6.3; TS 102 940 V2.1.1 clause 6.5 (every identifier-holding layer subscribes and derives its identifier from the HashedId8) | `id_change.hpp` (`IdChangeService`, `IdChangeHook`, `IdChangeResponder`), `security::IdentityManager`; the GN core is a subscriber (IF-GN-003) |
| IF-SF-001 | SF-IDCHANGE-*/SF-ID-LOCK/-UNLOCK for the facilities layer; VRU basic service stops VAM generation on PREPARE, resumes with the new StationId after COMMIT, locks in elevated-hazard situations; SF-SIGN/-VERIFY/-ENCRYPT/-DECRYPT/-ENCAP/-DECAP as parameter types only | [TS 102 723-9 V1.1.1](https://www.etsi.org/deliver/etsi_ts/102700_102799/10272309/01.01.01_60/ts_10272309v010101p.pdf) Tables 2 to 27, clause 4.1.5 (one entity serves several layers); TS 103 300-3 V2.3.1 clause 5.3.5 | `sf_sap.hpp`, served by the same `IdChangeService` instance as IF-SN-002; the subscriber may run in another task, process or device, the library defines no transport |
| IF-SEC-001 | Security encapsulation/decapsulation boundary | TS 102 723-8; TS 103 097 and TS 102 941 for security profiles/trust | `security::SecurityEntity` injected into the router: SN-ENCAP signing and, with `VIDF_SECURITY_VERIFY` (default on), SN-DECAP verification (IF-SEC-004); without it SN-DECAP reports Configuration_Problem (GAP-SEC-001) |
| IF-SEC-004 | Verification of received signed messages: protocol version, profile structure per ITS-AID, hashId/signature consistency, signer lookup (inline certificate or learned digest), ticket validity, permissions for the ITS-AID, chain to a provisioned trust anchor with every certificate signature verified, region, message signature; generationTime plausibility and replay per `VerificationPolicy`; P2P certificate distribution (request unknown AT/AA digests, learn an AA from `requestedCertificate`); learned certificates and replay window bounded | TS 103 097 V2.2.1 clauses 5.2, 7.1.1 to 7.1.3 (structure, P2P rules); IEEE Std 1609.2 clause 5.2 (SPDU validity), 5.3.1 (hashing with the signer certificate); TS 102 940 V2.1.1 clause 6 (trust chain root, AA, AT); TS 102 723-8 V1.1.1 Table 27 (report codes) | `security.hpp`: `check_profile()`, `verify_certificate_signature()`, `VerificationPolicy`, `SecurityEntity::decapsulate_packet`; upstream `DefaultCertificateValidator`, `CertificateCache`, `DefaultLocationChecker`; ported verify flow of upstream `StraightVerifyService::verify(v3)` |
| IF-SEC-002 | Signing profiles: CAM (signer digest, certificate once per second or on request), DENM (certificate, generationLocation), generic/GN-MGMT, VAM individual (1 s, new CAM signer) and cluster (500 ms via context information) with SSP `{0x01}`; certificate profiles for AT/AA/root/EC checked when a ticket is provisioned; hashing with the signer certificate hash; refusal without a valid ticket, permission or trust anchor | [TS 103 097 V2.2.1](https://www.etsi.org/deliver/etsi_ts/103000_103099/103097/02.02.01_60/ts_103097v020201p.pdf) clauses 5.2, 7.1.1 to 7.1.3, 7.2.1 to 7.2.4; IEEE Std 1609.2 clause 5.3.1; TS 103 300-3 V2.3.1 clauses 6.5.2 and 6.5.3; TS 102 965 V2.4.1 Table A.1 (ITS-AIDs) | `security.hpp`: `Ts103097SignHeaderPolicy`, `CertificatePool`, `TrustConfiguration`, `SecurityEntity::encapsulate_packet`; upstream `v3::StraightSignService`, `DefaultCertificateValidator` |
| IF-SEC-003 | ECDSA over NIST P-256, brainpoolP256r1 (SHA-256) and brainpoolP384r1 (SHA-384); compressed point recovery; key pair generation | IEEE Std 1609.2 clauses 5.3.1, 5.3.3, 6.3.38/6.3.39, 6.4.36; FIPS 186-4 D.1.2.3; RFC 5639 clauses 3.4/3.6 | `backend_mbedtls.hpp` (PSA Crypto of mbedTLS 3.6/4.1), `ecc.hpp` (decompression, y = rhs^((p+1)/4) as p = 3 mod 4 for all three curves); upstream `BackendOpenSsl` on the host |
| IF-PKI-001 | EnrolmentRequest/Response and AuthorizationRequest/Response with proof of possession, ECIES key encapsulation, AES-128-CCM, request hash, `pskRecipInfo` decryption of the response | [TS 102 941 V2.2.1](https://www.etsi.org/deliver/etsi_ts/102900_102999/102941/02.02.01_60/ts_102941v020201p.pdf) clauses 6.2.3.2 and 6.2.3.3, Annex A.2; TS 103 097 V2.2.1 clauses 5.2/5.3; IEEE Std 1609.2 clauses 5.3.5 (ECIES, KDF2, HMAC tag 128 bit) and 5.3.8 (CCM, nonce 12, tag 16); TS 102 965 V2.4.1 Table A.1 (623) | `pki.hpp`/`pki.cpp` with `ecies_openssl.cpp` (host) and `ecies_mbedtls.cpp` (PSA); `VIDF_PKI` off by default; no transport, CTL/CRL or scheduling (GAP-PKI-001) |
| IF-MN-001 | CORE_MMT.request/.response (time, position vector, GN address, TC mapping) from the N&T management entity; MN-GET/MN-SET of the DCC N-Params; MN-COMMAND/-REQUEST envelope | TS 103 836-4-1 V2.2.1 Annex K; EN 302 890-2 V2.1.1 clause 5.5.2; [TS 102 723-4 V1.1.1](https://www.etsi.org/deliver/etsi_ts/102700_102799/10272304/01.01.01_60/ts_10272304v010101p.pdf) clause 5; TS 103 175 V1.1.1 clause 8.3 and Table 10 | `mn_sap.hpp`, `management.cpp`: `CORE_MMT_response_apply(Stack&, ...)`, `NetworkParameterProvider`; no DCC values are invented (ErrStatus 250 "unsupported" when no provider) |
| IF-MF-001 | MF-SET of the DCC F-Params (channel number, available resource); MF-COMMAND/-REQUEST with ErrStatus 5 for an undefined number | [TS 102 723-5 V2.0.0](https://www.etsi.org/deliver/etsi_ts/102700_102799/10272305/02.00.00_60/ts_10272305v020000p.pdf) clause 5 incorporates V1.1.1; TS 103 175 V1.1.1 clause 8.4, Tables 11 to 13, clause 6.5 | `mf_sap.hpp`: `FacilitiesParameterSink` implemented by the facilities layer of the application |
| IF-MI-001 | MI-SET/MI-GET of the DCC I-Params (52 to 57) with MAC-ID and CommandRef; ErrStatus 5 for an undefined command | [TS 102 723-3 V1.1.1](https://www.etsi.org/deliver/etsi_ts/102700_102799/10272303/01.01.01_60/ts_10272303v010101p.pdf) clauses 5.2.3, 7 and 8, Tables 5 to 8; TS 103 175 V1.1.1 clause 8.2, Table 5 | `mi_sap.hpp`: `AccessParameterProvider` implemented by the access adapter; channel load and transmit timing are read from nowhere else |

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

Comment convention of the port headers: every type, primitive binding and
public function that represents a standardised object carries the standard,
edition and clause or table it comes from in the comment immediately above it;
members and helpers of such a type (accessors, bookkeeping, overrides of an
upstream interface, `using` aliases of another header's types) are covered by
the comment of the type or of the header they alias, and implementation
details (private members, `Impl` classes) carry none. The same convention
applies to the pre-existing `stack.hpp`/`access.hpp`.

The SN/SF/MN/MF/MI bindings are C++ representations of the primitives named
above. Their subscribers, providers and sinks may live in the same task, in
another task or process, or on another device; the library defines no transport
for them and no serialization other than `SN_ENCAP_request_submit`'s owned
packet. Identifiers are HashedId8 values of the ticket in use (TS 102 940
V2.1.1 clause 6.5); the GN MID takes the least significant six octets with the
locally administered bit set and the group bit cleared.

The R2 GN V2.2.1 edition introduces TRANSP_CORE/CORE_GAGH and MCO/ALI handling
beyond the older router's model. The interface and behavior gap must be closed
before claiming conformance to that edition. A pinned R2 facility ASN.1 codec
does not make every lower layer R2-compliant.
