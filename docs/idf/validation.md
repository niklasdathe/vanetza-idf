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
| Complete facilities/security ATS | Not executed | Full services and security integration remain incomplete |

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
