# Validation

No full-stack conformity is claimed. Results below were collected from this
port, not inferred from the upstream project or other firmware.

| Check | Result | Scope |
|---|---|---|
| Host build, GCC 13.2 | PASS | Network, CAM/DENM/VAM codecs and HIL enabled |
| Host component regression | PASS, 92 checks | Includes named NF request length/security/wire mapping, codecs, SHA, GN/BTP and radio frame handling |
| Official ETSI BTP control, host | PASS, 5/5 expected cases | Actual stack via named NF request/indication binding; unsecured PICS |
| ESP32-C5 build | PASS | ESP-IDF 6.0.2; 1,753,088-byte application, 3 MiB application partition |
| ESP32-C5 component execution | PASS | 92 on-device checks; HIL server now survives a JTAG/USB reset (see fix note below) |
| Official ETSI BTP control, device (COM20) | PASS, 5/5 expected cases | Real hardware SUT via `serial_sut.py`; same testcase objects and PICS as the host run |
| Raw GN-DATA N-SAP (IF-GN-002), host | PASS, manual round trip | SHB send (GN_DATA_request) and receive (on_receive_gn) verified byte-for-byte via `vidf_sut.exe`; see below |
| Official ETSI GeoNetworking control, host | **PASS, 1/3 executed cases**; 1 fail, 1 inconc (both legitimate scope gaps, not bugs) | `TC_GEONW_FDV_SHB_BV_01`; see below |
| Access/DCC campaign | Not executed | Required observations and behavior remain incomplete |
| Independent C5 radio pair, real RF (COM20→COM11) | **PASS**, 3/3 identical reruns | Real over-the-air transmit/receive between two boards; see below for the FCS-check fix |
| Host component regression, security on (Windows Debug, OpenSSL) | PASS, 629 checks | Security entity, identifier change, SN/SF/MN/MF/MI bindings, TS 102 941 core; PSA cross-check build (mbedTLS 4.1 from the IDF tree) PASS, 806 checks; security off 117; access-only 55; Linux Release 629 |
| ESP32-C5 component execution, security on (COM11) | PASS, 503 checks | PSA Crypto backend of mbedTLS 4.1.0; `CONFIG_VANETZA_IDF_PKI=y`; see [security-device-03](evidence/security-device-03/result.json) and the heap note below |
| ESP32-C5 component execution, security on (COM20, second board) | PASS, 503 checks | Same image, board recovered over JTAG; [security-device-04](evidence/security-device-04/result.json) |
| Official ETSI Security, GN-MGMT profile, host | **PASS 7/8**; 1 fail (testcase defect, IUT-independent) | `TC_SEC_ITSS_SND_GENMSG_01..08_BV`, framework-side signature verification enforced; see below |
| Official ETSI Security, CAM/DENM profiles, host | **PASS 7/7** | `TC_SEC_ITSS_SND_CAM_01..04_BV`, `TC_SEC_ITSS_SND_DENM_01..03_BV`; see below |
| Official ETSI BTP control, host, secured-capable SUT | PASS, 5/5 | Regression of the new `vidf_sut` build: [btp-host-05](evidence/btp-host-05/result.json) |
| Official ETSI GeoNetworking control, host, secured-capable SUT | pass/inconc/fail, identical to geonetworking-host-01 | [geonetworking-host-02](evidence/geonetworking-host-02/result.json): no regression |
| Security ATS receiving side, PKI ATS | Not executed | SN-DECAP verification does not exist (GAP-SEC-001); the TS 102 941 core has no transport (GAP-PKI-001) |
| Complete facilities ATS | Not executed | Full services remain incomplete |

The [BTP result](evidence/btp-host-04.json) records executable and configuration
hashes, timestamps and every testcase verdict. Its five cases are
TC_BTP_PGA_BV_01, TC_BTP_PGB_BV_01, TC_BTP_PGB_BV_02,
TC_BTP_PP_BV_01 and TC_BTP_PP_BV_02. There are no missing, unexpected or
duplicate verdicts in that run. The same five cases, same adapter and same
PICS pass against the real ESP32-C5 SUT over USB; see
[the device result](evidence/btp-device-01/result.json).

The [C5 build record](evidence/c5-build.json) pins the application, bootloader,
partition table and configuration hashes.

### HIL server reset fix

`examples/esp_idf_test`'s `run_hil_server()` previously never returned control
after printing `VIDF_TEST_RESULT=0` on a JTAG- or USB-triggered reset (as opposed
to a full power-on reset): the ESP32-C5 ROM's UART0 initialization waits forever
for a clock-ready bit that such a reset can leave cleared. The parent project's
own firmware hit and fixed the identical issue
(`implementation/firmware/main/usb_hil.c:75`); this port did not carry that fix.
`hil_server.cpp` now sets `PCR_UART0_SCLK_EN` before installing the USB-Serial/JTAG
driver, guarded by `CONFIG_IDF_TARGET_ESP32C5`. Confirmed on the COM20 board across
repeated resets. The COM11 receiver board needed one physical power cycle to
recover from the pre-fix hang before it would boot the corrected image; a JTAG
halt/resume showed it genuinely spinning in ROM, not merely slow to answer.

The external BTP source revision is
`3576386312f9dff1afcccc8f96247876ab9a0865`; the external framework revision is
`e477d327f4df850e487feab5c0f68b1044db3cf1`. Official testcase objects are reused;
the library supplies the SUT port adapter. These older tests do not by themselves
prove every Release 2 requirement.

### GN-DATA N-SAP (IF-GN-002) and a real upstream fix

The GeoNetworking ATS's SHB/GBC "generate message" UT triggers send a raw test
SDU with the Common Header `next_header` set to "Any" (no BTP/IPv6 framing).
`Stack` previously had no way to originate that: `Stack::request(BtpRequest)`
always sets a BTP next-header, and the upstream router's
`CommonHeader(const DataRequest&, const MIB&)` constructor only handled
`UpperProtocol::BTP_A`, `BTP_B` and `IPv6` in its switch, throwing
`"Unhandled upper protocol"` for anything else — `UpperProtocol::Unknown` is a
real, documented value (the router itself assigns it on receive for
unrecognized next-headers), so this was a genuine gap, not a deliberate
exclusion. Two changes close it:

- `vanetza/geonet/common_header.cpp`: the switch now maps
  `UpperProtocol::Unknown` to `NextHeaderCommon::Any`, matching what the
  default constructor already produces.
- `Stack` gained `GnRequest`/`GnIndication` and `request(GnRequest)`/
  `on_receive_gn(...)`: the same SHB/GBC-only validation as `BtpRequest`, but
  with a raw payload and no header construction, registered against the
  router's `UpperProtocol::Unknown` transport handler alongside the existing
  BTP_A/BTP_B ones.

Verified with `vidf_sut.exe` (opcodes `3`=GN_DATA_request SHB,
`4`=update_position, both new; `2`=AlDataIndication, already existing and
transport-agnostic): a raw `"HELLO"` SHB request produces a GN packet with
Common Header `next_header=0x00` (Any) and the exact payload at its tail;
feeding those same wire bytes back through `AlDataIndication` produces a
GN-DATA.indication with `upper_protocol=Unknown` and the same `"HELLO"`
payload back out. `vidf_tests.exe` still passes 92/92 after the change.

### GeoNetworking TTCN adapter: one official case passes

`ports/esp_idf/tests/etsi_geonetworking_adapter.cpp` implements the three
GeoNetworking test-port classes (`GeoNetworkingPort`, `UpperTesterPort`,
`AdapterControlPort`) against the official `AtsGeoNetworking` testcase
objects, built the same way as the BTP adapter
(`build_etsi_geonetworking_adapter.py`). `PICS_GN_LOCAL_GN_ADDR` in
[etsi_geonetworking.cfg](../../ports/esp_idf/tests/etsi_geonetworking.cfg) is
set to the exact address `hil_sut.cpp`'s `Sut::reset()` gives the stack
(`typeOfAddress=e_initial, stationType=e_unknown, mid=02:00:00:00:00:01`);
`f_acGetLongPosVector` compares against this value exactly, so it is not an
arbitrary PICS choice. `PICS_GN_BASIC_HEADER`/`COMMON_HEADER` are disabled
because those testcases send deliberately malformed headers expecting
rejection, which this adapter does not implement; everything else the ATS
defaults to "supported" is disabled to match GAP-GN-001 (only SHB is wired
into the adapter; GBC/GUC/GAC/TSB triggers are not).

Under that PICS selection, three cases execute (this is the complete
population `PICS_GN_SHB_SRC` reaches):

| Testcase | Component | Verdict | Why |
|---|---|---|---|
| `TC_GEONW_FDV_SHB_BV_01` | single (`ItsGeoNetworking`) | **pass** | See below |
| `TC_GEONW_PON_FPB_BV_11_05` | multi (`ItsMtc`) | inconc, immediately | Its body additionally requires `PICS_GN_GUC_SRC`, which is correctly disabled (GAP-GN-001) |
| `TC_GEONW_PON_SHB_BV_01` | multi (`ItsMtc`) | fail | Needs a second, independently-addressable simulated station (PTC); this adapter models one IUT only |

Getting `TC_GEONW_FDV_SHB_BV_01` to a genuine pass took fixing two real bugs,
neither of which was in the testcase logic:

**1. A null-pointer bug in the external ETSI framework's codec.**
`geonetworking_codec::decode_` (`ccsrc/Protocols/GeoNetworking/geonetworking_codec.cc`)
unconditionally dereferences `_params` while writing the decoded payload, in
all three branches of its length-alignment logic. Every *other* parameter
write in that file — a few lines up, in the enclosing `decode()` — is
correctly guarded with `if (_params != NULL)`; this one payload branch just
wasn't. `fx__dec__GeoNetworkingPdu` (`ccsrc/EncDec/LibItsGeoNetworking_Encdec.cc`)
always calls `decode()` with the default `params` (`nullptr`), so decoding
*any* `GeoNetworkingPdu` through the official codec wrapper segfaults as
soon as it reaches that field. This was never triggered by BTP (whose
adapter never calls this decoder) or by any earlier GeoNetworking attempt,
because no GN packet had ever actually been transmitted-and-observed through
TITAN before fix 2 below — every earlier SHB trigger just sat unsent, so the
buggy decode path was never reached.

Confirmed with a real core dump: `ulimit -c unlimited`, a fixed
`/proc/sys/kernel/core_pattern` (WSL redirects it to a pipe by default,
which silently swallows core files), and `gdb -batch -ex 'bt full'` on the
result showed the crash precisely, four frames past `abort()` inside
`std::map<...>::operator[]` called from `geonetworking_codec::decode_` line
257, `this=0x8` (a null `_params` plus a small member offset). No debugger
was installed in the WSL environment initially; installing one (`apt-get
install gdb`) is what turned "reproducibly crashes for an unknown reason"
into an exact line number.

Per the framework's own stated policy (never edit the pinned ETSI source
tree or its testcase objects), the fix is a disposable build overlay:
`build_etsi_geonetworking_adapter.py` reads the pinned `geonetworking_codec.cc`,
applies three `if (_params != NULL)` guards in memory, compiles the patched
copy into its own `--out` directory, and links that instead of the original
`.o` — the checked-out framework source on disk is never written. This
mirrors the project's existing `AtsIPv6OverGeoNetworking` overlay precedent
(`tools/ttcn/validation-status.json`'s `suite_overlay` entries): before/after
source hashes are recorded in the adapter's own `build.json`
([geonetworking-host-01/adapter-build.json](evidence/geonetworking-host-01/adapter-build.json)).

**2. `Stack` never applied its own configured GN address.**
With the codec crash fixed, the SHB packet decoded fine but failed the
match: the test's `mw_longPosVectorPosition` template requires the observed
source position vector's `gnAddr` to equal exactly what `AcGnPrimitive::getLongPosVector`
reported, and the two disagreed. `hil_sut.cpp`'s `Sut::reset()` sets
`config.mib.itsGnLocalGnAddr.mid({2,0,0,0,0,1})`, but `Router::update_position()`
(`vanetza/geonet/router.cpp`) only ever touches `m_local_position_vector`'s
timestamp/latitude/longitude/speed/heading — never its address. The address
field of a station's own position vector is populated exclusively by a
separate method, `Router::set_address(const Address&)`, which `Stack` never
called. So every transmitted packet actually carried the *default*
`vanetza::geonet::Address()` (all-zero `mid`, not manually configured),
regardless of what the caller put in `mib.itsGnLocalGnAddr` — BTP's ATS
never checks the source GN address, so this was invisible until
GeoNetworking's did. Fixed with one call in `Stack::Impl`'s constructor
(`ports/esp_idf/src/stack.cpp`): `router.set_address(cfg.mib.itsGnLocalGnAddr);`

With both fixed, `TC_GEONW_FDV_SHB_BV_01` passes: initialize,
`AcGnPrimitive::getLongPosVector`, the beacon feed through
`AdapterControlPort` (`f_startBeingNeighbour`'s whole purpose — giving the
router a location-table neighbour so `TrafficClass.scf` doesn't buffer the
SHB request instead of transmitting it immediately), the `UtGnTrigger::shb`
request, and the resulting SHB packet's observed header fields (including
the now-correct source address) all match exactly
(see [the MTC log](evidence/geonetworking-host-01/AtsGeoNetworking.framework-dathe-mtc.log)).
Rerun three times back to back with an identical verdict every time: not a
fluke.

`TC_GEONW_PON_SHB_BV_01` and `TC_GEONW_PON_FPB_BV_11_05` both declare
`runs on ItsMtc` and use a second config (`CF02`/`CF03`) that models an
independent simulated station (`ItsNodeB`/`ItsNodeA`) as a genuine parallel
test component (PTC), each mapping its own port set. This adapter, like the
BTP one, models exactly one IUT connection; extending it to back a PTC's
ports too (so the "other station" is also a real, addressable simulated
peer rather than the same single `Process`/SUT singleton) is unimplemented.
`PON_FPB_BV_11_05` happens to end INCONC before reaching that requirement
(its own PICS gate on `PICS_GN_GUC_SRC` triggers first), so this gap is only
actually exercised, and confirmed as a fail, by `PON_SHB_BV_01`.

Evidence: [geonetworking-host-01](evidence/geonetworking-host-01/result.json)
(host SUT, native Linux build — WSL interop could not pipe stdin/stdout to a
Windows-built host executable, so the host SUT for this suite is built
natively per [test-campaigns.md](test-campaigns.md)).

### Security entity, cross-layer SAPs and the AtsSecurity campaigns

The security work (branch `feature/etsi-cross-layer-security`, one commit per
increment) adds a signing security entity, the identifier change of
TS 102 723-8 clause 6.3, the SN/SF/MN/MF/MI bindings and the TS 102 941
request/response core; [standards.md](standards.md) lists the clauses. Every
result below comes from this port.

**Crypto backend.** `BackendMbedTls` uses only the PSA Crypto API because
ESP-IDF 6.0.2 ships mbedTLS 4.1.0 (TF-PSA-Crypto), whose classic ecp/bignum
headers are private. PSA imports Weierstrass public keys only in uncompressed
form, so compressed IEEE 1609.2 points are recovered by `vanetza_idf::ecc`
(y = rhs^((p+1)/4), p = 3 mod 4 for NIST P-256 and both Brainpool curves).
The host tests run the same backend against OpenSSL as an oracle (signature
cross-verification, decompression against `EC_POINT_set_compressed_coordinates`,
known-answer vectors in `test_backend_kat.cpp`) in the `VIDF_MBEDTLS_ROOT`
build (806 checks); the device runs the PSA path natively (503 checks, the
difference being the OpenSSL-only oracle tests).

**Trust and refusal.** `CertificatePool::add` checks the TS 103 097 clause
7.2.1 ticket profile and probes the key against the certificate (sign then
verify) before accepting it; `TrustConfiguration` anchors roots and AAs; the
entity refuses a request without a valid ticket for the ITS-AID/SSP, with an
expired ticket, or with a ticket whose issuer is not anchored, and counts each
refusal. Nothing is transmitted unsigned when `itsGnSecurity` is set, and
`decapsulate_packet` reports `Configuration_Problem`/`Unsigned_Message`, never
success (`test_fail_closed`).

**Identifier change.** `IdentityManager` runs PREPARE/COMMIT/ABORT/DEREG rounds
with a response timeout (default 500 ms), lock with expiry, deferred responders
(a subscriber may answer from another context) and re-entrancy guarding; the
GN core subscribes when `itsGnLocalAddrConfMethod` is ANONYMOUS, marks
`identity_change_pending` on PREPARE, flushes the forwarding buffers and
rewrites the MID from the committed HashedId8 (least significant six octets,
locally administered bit set); the SF binding drives a VRU-style subscriber in
`test_sf_facilities_hook`. The corresponding Linux Release run initially
segfaulted in that test: the entity was destroyed after the subscriber it
notifies on DEREG had gone out of scope (a use-after-scope in the *test*, not
the library), fixed by scoping the entity's lifetime explicitly.

**Upstream Vanetza changes (additive only).** `SignRequest::context_information`
and `DataRequest::security_context` carry the SN-ENCAP context information from
BTP/GN request to the security entity (`Router::encap_packet` gained the
parameter); `Router::flush_forwarding_buffers()` is public so the GN core can
drop buffered packets carrying the old identifier on PREPARE. Nothing else in
`vanetza/` changed. One upstream bug was found and worked around in the tests
rather than patched: `v3::SecuredMessage::get_inline_p2pcd_request()` widens
each 3-octet `HashedId3` through an 8-octet conversion and truncates the wrong
end, so `test_signing_profiles` reads the ASN.1 field directly.

**AtsSecurity campaigns.** `etsi_security_adapter.cpp` implements the
`ItsSecSystem` ports (GeoNetworking, GN/CAM/DENM upper testers, adapter
control) against the official `AtsSecurity` testcase objects
([build_etsi_security_adapter.py](../../ports/esp_idf/tools/build_etsi_security_adapter.py),
[adapter-build.json](evidence/security-host-01/adapter-build.json)). The
host SUT is `vidf_sut --security-pool ./certificates`, the pool an isolated test
trust domain written by `vidf_test_pool` in the framework's own loader layout
(hashes in each `result.json`). Three properties of the run matter for reading
the verdicts:

1. *Verification is the framework's.* Secured transmissions are unwrapped by
   `security_services_its::verify_and_extract_gn_payload` with
   `enable_security_checks=1`, so a failed signature/digest/generation-time
   check discards the packet instead of passing it up with a warning; a PASS
   therefore includes a signature the framework verified against
   `CERT_IUT_A_AT`, not only the template match.
2. *One SUT per campaign, shared across TITAN components.* TITAN's parallel
   runtime forks the MTC and each PTC from the host controller; the DENM cases
   trigger from a PTC while the MTC observes the GN port. The adapter starts the
   SUT once in the host controller before any fork and serialises every
   command/reply exchange with a process-shared robust mutex; the DENM carrier
   is deferred to the next clock advance so the transmission surfaces on the
   component that owns the GN port.
3. *Two stimulus configurations, no per-testcase switching.* A running CAM
   carrier restarts the beacon timer with every SHB (TS 103 836-4-1 clause
   10.3.5), so the GN-MGMT cases run with the carrier off
   ([etsi_security_gn.cfg](../../ports/esp_idf/tests/etsi_security_gn.cfg))
   and the CAM/DENM cases with it on
   ([etsi_security_facilities.cfg](../../ports/esp_idf/tests/etsi_security_facilities.cfg),
   `PX_GN_UPPER_LAYER := e_btpB`). The carriers are syntactically valid
   Release 2 CAM (SHB) and DENM (GBC into a 500 m circle, TS 103 831 clause
   5.4.2) PDUs of the test application; no CA/DEN service is claimed.

Verdicts ([security-host-01](evidence/security-host-01/result.json),
[security-host-02](evidence/security-host-02/result.json)):

| Case | Verdict | Note |
|---|---|---|
| `TC_SEC_ITSS_SND_GENMSG_01..04, 06..08_BV` | pass | Secured beacons, psid 141, digest/certificate alternation, generationTime, signedData payload |
| `TC_SEC_ITSS_SND_GENMSG_05_BV` | **fail** | The testcase compares `validityPeriod.start` (Time32, seconds) with a range built from `v_curTime` in microseconds (pinned `ItsSecurity_TestCases.ttcn` line 7313; unchanged at the upstream master's line 6672), so no IUT passes it. The test purpose's own condition (start <= generation time < start + duration) holds for the logged values. Retained, not tuned; [analysis](evidence/security-host-01/analysis.md) |
| `TC_SEC_ITSS_SND_CAM_01..04_BV` | pass | psid 36, headerInfo without expiry/location, signer digest or certificate with appPermissions |
| `TC_SEC_ITSS_SND_DENM_01..03_BV` | pass | psid 37, generationLocation present, GBC packet |

The receiving-side cases (`TC_SEC_ITSS_RCV_*`) were not executed: the SUT
cannot verify, and running them would only document INCONC.

**Device heap.** The first device run with security failed in `test_fail_closed`
with "OER decoding failed" ([security-device-02](evidence/security-device-02/result.json)).
Section markers now print the free heap on the device; the re-run showed 14 kB
free when the asn1c copy failed, with five test stations (router, security
entity, trust domain each) alive at once, 25-45 kB apiece. The test scopes each
scenario now; the library was not changed
([security-device-03](evidence/security-device-03/console.txt), 112 kB free at
every section). Sizing note for applications: one secured station on the C5
test firmware leaves roughly 110 kB of the internal heap.

**Board recovery.** That failing device run also left the board unflashable
("Write timeout" from esptool): the ROM UART0 clock-enable repair described
above lived in `run_hil_server()`, which a failed test run never reaches, so
the next USB-triggered warm reset hung in ROM. `app_main` applies the repair
first now. The board still running the older image (COM20) was recovered over
JTAG instead: OpenOCD halts the core, sets `PCR_UART0_SCLK_EN` before each
`program_esp` step and programs the three images
([security-device-04](evidence/security-device-04/result.json), `openocd-flash.log`);
that board then passed the same 503 checks and accepts a plain esptool reset again.

### Independent C5 radio pair: a real bug in an "FCS" check that could never pass

`radio_pair.py`'s independent two-board radio test (COM20 transmits, COM11
receives, over real RF) initially failed on every run with "no exact
independent frame with valid FCS observed", even though the frame's actual
content — every header field and the full application payload — decoded
correctly. Decoding the raw captured bytes by hand (initially mis-modeling
`ShbHeader` as a 24-byte `LongPositionVector` with no trailing field, which
made 8 bytes look unaccounted for instead of 4) led to the real structure:
`vanetza::geonet::ShbHeader` is `LongPositionVector` (24 bytes) **plus a
4-byte reserved `DccField`** (`vanetza/geonet/shb_header.hpp`); once that's
accounted for, the frame is exactly 102 bytes of correct content plus a
4-byte trailer.

That trailer is not a real FCS. Three separate captures with completely
different random payloads all produced the *identical* trailing 4 bytes
(`00 00 99 00`) — direct proof the value is not content-derived and can
never match a recomputed CRC32, regardless of whether the frame was received
correctly. Two independent facts explain why checking it was never
necessary in the first place:

- `vanetza_idf::C5Radio`'s promiscuous filter (`ports/esp_idf/src/c5_radio.cpp`)
  never sets `WIFI_PROMIS_FILTER_MASK_FCSFAIL` ("Filter the FCS failed
  packets, do not open it in general" — Espressif's own comment on that
  flag). Any frame reaching the receive callback at all has already passed
  a real, hardware-validated FCS check; there is nothing left to verify at
  the software level.
- `rx_ctrl.sig_len` on this chip is documented in `esp_wifi_he_types.h`
  (this chip's 802.11ax/HE RX descriptor) as "the length of the reception
  MPDU" — not "MPDU + FCS" as the ESP-IDF documentation for older,
  non-HE ESP32 chips states, which is what `c5_radio.cpp`'s previous comment
  was written against.

Fixed by checking content match only — which is what "the independent
receiver correctly received what the DUT transmitted" actually means here —
and correcting the comments in `c5_radio.cpp`, `its_g5_frame.hpp` and
`radio_pair.py` that assumed the trailing bytes were a real FCS. The
trailing bytes are still captured and reported (`result.json`'s
`trailing_bytes`) for inspection, just no longer gated on. Verified stable
across three consecutive real-RF reruns
([evidence](evidence/radio-pair-01/result.json)), each with a fresh random
payload and an identical `00 00 99 00` trailer.

See [campaign instructions](test-campaigns.md) and
[interface/capability assessment](interface-assessment.md) for remaining work.
