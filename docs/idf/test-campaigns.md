# Running external test campaigns

Install and build the official ETSI TTCN-3 framework separately. This library
does not install TITAN, supply the ETSI suites or replace their verdict logic.
The adapter build helper links the user's compiled BTP suite with this library's
test-port adapter; it preserves the official testcase objects.

## BTP

`ports/esp_idf/tools/run_etsi.py` accepts the external TITAN installation,
compiled suite and configuration. On Linux, for example:

```sh
python3 ports/esp_idf/tools/run_etsi.py \
  --titan /path/to/titan/Install \
  --binary /path/to/adapted/AtsBTP \
  --config ports/esp_idf/tests/etsi_btp.cfg \
  --expected-cases ports/esp_idf/tests/etsi_btp_cases.json \
  --sut /path/to/vidf_sut \
  --out /path/to/new-result-directory
```

The host SUT and device SUT use `NF_SAP::BTP_DATA_request` and map reception
through `BTP_DATA_indication`. Lower test records come from the real router.
For hardware, select a Python executable as `--sut`, the absolute
`ports/esp_idf/tools/serial_sut.py` path as `--sut-script`, and the DUT's
serial port as `--port`. The example `esp_idf_test` firmware must already be
built, flashed and running its HIL server. WSL requires Windows Python and a
Windows script path to access a Windows COM port.

Retain `result.json`, `test.cfg`, `expected-cases.json`, the MTC log and console
log. The result includes executable/configuration hashes and individual
verdicts. A complete campaign has exactly one verdict per expected testcase.

The provided five-case campaign establishes only its selected BTP behavior.
It does not validate GeoNetworking routing, facilities service behavior,
security, DCC or the physical radio. Those need their own applicable suites,
PICS/PIXIT and test-port implementations. Never acknowledge an unsupported
upper-tester command merely to let a suite advance.

## GeoNetworking

`ports/esp_idf/tools/build_etsi_geonetworking_adapter.py` builds
`ports/esp_idf/tests/etsi_geonetworking_adapter.cpp` against a separately
compiled `AtsGeoNetworking`, the same way as the BTP adapter. It implements
`GeoNetworkingPort`, `UpperTesterPort` and `AdapterControlPort`; only SHB
triggering/observation is wired up (GAP-GN-001), so
[etsi_geonetworking.cfg](../../ports/esp_idf/tests/etsi_geonetworking.cfg)
disables every other PICS the ATS defaults to "supported".

```sh
python3 ports/esp_idf/tools/build_etsi_geonetworking_adapter.py \
  --etsi /path/to/TS.ITS --titan /path/to/titan/Install \
  --out /path/to/new-build-directory
python3 ports/esp_idf/tools/run_etsi.py \
  --titan /path/to/titan/Install \
  --binary /path/to/new-build-directory/AtsGeoNetworking \
  --config ports/esp_idf/tests/etsi_geonetworking.cfg \
  --expected-cases ports/esp_idf/tests/etsi_geonetworking_cases.json \
  --sut /path/to/vidf_sut \
  --out /path/to/new-result-directory
```

**The host SUT must be a native Linux build**, unlike BTP's Windows
`vidf_sut.exe`: piping this adapter's stdin/stdout to a Windows executable
launched through WSL interop silently drops the piped input (the SUT process
reads EOF immediately and exits), which is indistinguishable from a crash
until you check for it directly. Configure and build `ports/esp_idf` with
CMake/Ninja inside WSL against the distribution's own Boost dev package
(`apt install cmake ninja-build libboost-dev libboost-date-time-dev`); do
this from a native Linux path (e.g. `/root/...`), not `/mnt/c/...` — building
from the Windows-mounted path works but is dramatically slower (large,
many-small-file compiles can stall for many minutes) because every header
read crosses the 9P filesystem boundary. Apt's Boost is missing
`boost/core/invoke_swap.hpp`, which `boost/geometry/formulas/karney_inverse.hpp`
needs; naively copying it from `external/esp-boost` redefines symbols already
in apt Boost's `boost/core/swap.hpp` and fails to compile for a different
reason. `ports/esp_idf/third_party/geometry/include/boost/core/invoke_swap.hpp`
is a from-scratch compatibility shim (not a copy of upstream Boost) that
builds `invoke_swap` on top of the already-present `boost::swap()` instead of
redefining anything, so it works when combined with either Boost source. On
Windows (`VIDF_BOOST_ROOT` pointing at `external/esp-boost`) only one Boost
variant is ever in play, so this file is present but never actually reached
by the include search there.

`build_etsi_geonetworking_adapter.py` also applies a disposable build overlay
for a null-pointer bug in the external framework's own
`geonetworking_codec.cc` (decoding any `GeoNetworkingPdu` through the
official `fx__dec__GeoNetworkingPdu` wrapper segfaults, since it always
decodes with `params=nullptr` and one payload-decode branch dereferences
that unconditionally). The pinned source on disk is read but never written;
see docs/idf/validation.md for the full diagnosis and
[the recorded before/after hashes](evidence/geonetworking-host-01/adapter-build.json).

Device execution has not been attempted for this suite.

## Independent radio reception

After flashing the test application on two C5 boards, use:

```sh
python ports/esp_idf/tools/radio_pair.py \
  --dut COM20 --receiver COM11 --channel 180 \
  --allow-transmission --out /path/to/new-radio-result-directory
```

This integration test explicitly enables laboratory transmission. It checks
that receive-only mode rejects transmission, injects a unique payload at BTP,
sends the resulting GN packet through the DUT radio and checks an independent
receiver's raw frame byte-for-byte against exactly what the DUT submitted.
It retains a PCAP and a JSON result. Both radios are stopped during cleanup;
cleanup failures are reported.

The captured frames are not independently re-validated for FCS: the
receiver's promiscuous filter never sets `WIFI_PROMIS_FILTER_MASK_FCSFAIL`,
so the ESP32-C5 WiFi hardware has already discarded any frame that failed
FCS before this callback ever runs. `rx_ctrl.sig_len` on this chip is
documented as "the length of the reception MPDU" (`esp_wifi_he_types.h`),
not "MPDU + FCS" as older-chip ESP-IDF documentation states; measured
directly, it is 4 bytes longer than the actual frame, and those 4 trailing
bytes are a fixed value independent of frame content (confirmed across
captures with different random payloads) — not a real, software-recoverable
FCS. They are still written into the pcap for inspection
(`result.json`'s `trailing_bytes`), just not checked against anything.

The diagnostic radio commands are application test hooks, not ETSI primitives:
3 configures channel and transmit enable; 4 submits an AL_DATA request; 5 drains
independent receive observations; 6 stops the radio. These hooks can support an
external access test adapter. They do not themselves produce ETSI verdicts.

A matched frame establishes that particular reception. It cannot establish
spectral mask, frequency accuracy, receiver sensitivity, EIRP, congestion
control behavior or complete ITS-G5 compliance.
