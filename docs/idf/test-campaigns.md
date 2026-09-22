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
reason. `ports/esp_idf/compat/include/boost/core/invoke_swap.hpp`
is a from-scratch compatibility shim (not a copy of upstream Boost) that
builds `invoke_swap` on top of the already-present `boost::swap()` instead of
redefining anything, so it works when combined with either Boost source. The
`compat/include` directory is appended after every real Boost include root,
so the shim is only reached when the selected Boost lacks the header; with
`VIDF_BOOST_ROOT` pointing at a complete Boost it is never used.

`build_etsi_geonetworking_adapter.py` also applies a disposable build overlay
for a null-pointer bug in the external framework's own
`geonetworking_codec.cc` (decoding any `GeoNetworkingPdu` through the
official `fx__dec__GeoNetworkingPdu` wrapper segfaults, since it always
decodes with `params=nullptr` and one payload-decode branch dereferences
that unconditionally). The pinned source on disk is read but never written;
see docs/idf/validation.md for the full diagnosis and
[the recorded before/after hashes](evidence/geonetworking-host-01/adapter-build.json).

Device execution has not been attempted for this suite.

## Security

`ports/esp_idf/tools/build_etsi_security_adapter.py` links
`ports/esp_idf/tests/etsi_security_adapter.cpp` with a separately compiled
`AtsSecurity` (official testcase objects unchanged; the framework's own
GeoNetworking/CAM/DENM port objects are replaced, the same disposable
`geonetworking_codec.cc` overlay as for GeoNetworking is applied to this build
only). The adapter covers the sending side: GN-MGMT beacons through the GN core,
CAM and DENM carriers from the test application behind the upper tester ports,
and the receiving side through the third configuration below.

Generate an isolated test trust domain in the framework's certificate pool
layout, then run the two configurations (the GN-MGMT cases must run without the
CAM carrier, which restarts the beacon timer, TS 103 836-4-1 clause 10.3.5):

```sh
cmake -S ports/esp_idf -B build-host -DVIDF_TESTS=ON -DVIDF_SECURITY=ON
cmake --build build-host
./build-host/vidf_test_pool /path/to/new-pool-directory        # <name>.oer, <name>.vkey, index.lst
python3 ports/esp_idf/tools/build_etsi_security_adapter.py \
  --etsi /path/to/TS.ITS --titan /path/to/titan/Install \
  --out /path/to/new-build-directory
python3 ports/esp_idf/tools/run_etsi.py \
  --titan /path/to/titan/Install \
  --binary /path/to/new-build-directory/AtsSecurity \
  --config ports/esp_idf/tests/etsi_security_gn.cfg \
  --expected-cases ports/esp_idf/tests/etsi_security_gn_cases.json \
  --sut ./build-host/vidf_sut --sut-args "--security-pool ./certificates" \
  --pool /path/to/new-pool-directory \
  --out /path/to/new-result-directory-gn
python3 ports/esp_idf/tools/run_etsi.py \
  --titan /path/to/titan/Install \
  --binary /path/to/new-build-directory/AtsSecurity \
  --config ports/esp_idf/tests/etsi_security_facilities.cfg \
  --expected-cases ports/esp_idf/tests/etsi_security_facilities_cases.json \
  --sut ./build-host/vidf_sut --sut-args "--security-pool ./certificates" \
  --pool /path/to/new-pool-directory \
  --out /path/to/new-result-directory-facilities
```

`--pool` copies the pool to `<out>/certificates` (the SUT reads it from there
through `--sut-args`, the testcases through `PX_CERTIFICATE_POOL_PATH`/
`PX_IUT_SEC_CONFIG_NAME`) and records each file's hash. The SUT must be a
native Linux build, as for GeoNetworking. Pool tickets start one minute before
generation and last 24 hours; regenerate the pool for a campaign run later
than that.

The `[TESTPORT_PARAMETERS]` of both configurations set
`enable_security_checks=1` on the GeoNetworking port: the framework's own
security services verify every transmission of the SUT against the pool and a
failed verification discards the packet. `system.utPort.params` selects the
CAM carrier period of the test application (`cam_carrier_ms`), the only
stimulus difference between the two configurations. `AcEnableSecurity` names
the certificate the *test system* would sign with; the adapter accepts it when
it exists in the pool and applies the enforcement flag, but signs no
test-system packets.

A third configuration, `etsi_security_receive.cfg` with
`etsi_security_receive_cases.json` (26 receiving-side cases), needs a SUT built
with `VIDF_SECURITY_VERIFY` (the default). The test system signs its CAMs and
DENMs in TTCN-3 with `CERT_TS_A_AT`, or with `CERT_TS_B_AT` (a ticket restricted
to a 5 km circle around the SUT position) where the testcase uses
`PX_AT_CERTIFICATE`; the adapter injects them and reports what the SUT passes up
after SN-DECAP as `UtGnEventInd`. The SUT trusts both AAs of the pool
(`--aa` is repeatable; the defaults are `CERT_IUT_A_AA` and `CERT_TS_A_AA`).

Expected outcome with this library (retained in `docs/idf/evidence/security-host-09`,
`-10` and `-08`; earlier -06/-07/-05 identical): sending side 14 of 15
(`TC_SEC_ITSS_SND_GENMSG_05_BV` fails on a unit defect of the testcase), receiving
side 24 of 26 (`TC_SEC_ITSS_RCV_DENM_01_BV` and `DENM_02_BV_XX` error on a
declaration-order defect of the testcases); docs/idf/validation.md has both
analyses. Device execution of this suite has not been attempted; the device runs
the same security entity in the component tests (`security-device-06`).

### Issuing credentials outside the test pool: `vidf_issue`

`vidf_test_pool` writes the ETSI-named pool with fresh keys. `vidf_issue` (built
with the tests, host OpenSSL) issues the same certificate profiles for keys and
names of your choosing, so a chain under a real root can be produced and the
station's signed frames checked by tools that know nothing of this library:

```sh
vidf_issue root      --key root.pem --name "Example Root CA" --id ROOT --out chain     # self-signed (clause 7.2.3)
vidf_issue authority --issuer chain/ROOT.oer --issuer-key root.pem --name "Example AA" --id AA --out chain
vidf_issue ticket    --issuer chain/AA.oer --issuer-key chain/AA.vkey --root chain/ROOT.oer --id AT \
                     --permission 36:01FFFC --permission 141 --permission 638:01 --out chain
vidf_issue show chain/AT.oer                              # digest, issuer, validity, permissions, region
vidf_issue verify chain/AT.oer chain/AA.oer chain/ROOT.oer  # signatures, validity/region nesting, permission consistency
```

`--key`/`--issuer-key` accept a PEM private key (an encrypted PKCS#8 file is
opened with OpenSSL's pass-phrase prompt; the pass phrase is never an argument)
or a raw 32-octet `.vkey` as the pool writes it; `--start`/`--years`/`--hours`
set the validity (the default start is an hour ago but never before the
issuer's own start), `--region LAT,LON,RADIUS_M` (1/10 microdegrees, metres) a
circular ticket region. `root` writes the EU CCMS CPOC Protocol Release 3.0
profile (certIssuePermissions with minChainLength 2 and eeType app+enrol for
CA/DEN/VRU/GN-MGMT and the end-entity part of psid 623, a second group for the
authorities' psid 623 SSPs; CRL/CTL appPermissions), or with `--like
OTHER.oer` the permissions and region of an existing root (a rehearsal twin of
a real root with a throwaway key). `authority` derives its issuing
permissions from the issuer (every group that reaches two certificates down,
IEEE Std 1609.2 6.4.28, with chain length 1) and inherits the issuer's region
(6.4.17); `ticket` inherits the issuer's region unless `--region` is given and
carries the SSPs of TS 102 941 V2.2.1 Table B.6 for psid 623 where relevant.
Every command checks the result the way the receive-side verifier will
(signatures, validity nesting, region nesting, permission consistency, with
`--root` over the full chain) and writes nothing that would fail. The output
directory gets `<id>.oer`, `<id>.vkey` (except for `root`, whose key stays
where it was) and an `index.lst`, i.e. a pool `vidf_sut --security-pool`
loads with `--root ROOT --aa AA --at AT`.

Rules for a production root: run the tool where the root key lives, never copy
the encrypted PEM or its pass phrase anywhere, and keep the generated `.vkey`
files with the same care as the PEM. Nothing in the tests uses a project key;
the component tests and the pool generate throwaway keys per run.

### A distribution centre on localhost (CTL and CRL)

Receivers that take their AA certificates from the root's CTL rather than from
P2P distribution need the root's distribution centre (TS 102 941 V2.2.1 clause
6.3, Annex D). Until the real DC is up, the same interface runs on localhost:

```sh
vidf_issue ctl --issuer chain/ROOT.oer --issuer-key root.pem --aa chain/AA.oer=http://aa.example/ \
               --dc http://127.0.0.1:8080/ --sequence 1 --out lists/ctl-<HASHEDID8>.oer
vidf_issue crl --issuer chain/ROOT.oer --issuer-key root.pem [--revoke <HASHEDID8>]... --out lists/crl-<HASHEDID8>.oer
python3 ports/esp_idf/tools/local_dc.py --dir lists --port 8080       # GET /getctl/<HASHEDID8>, /getcrl/<HASHEDID8>
python3 ports/esp_idf/tools/fetch_trust_lists.py --dc http://127.0.0.1:8080/ --root chain/ROOT.oer --out fetched
vidf_issue inspect fetched/ctl-<HASHEDID8>.oer --root chain/ROOT.oer  # clause 6.3.6 checks, then the entries
```

The station applies what `fetch_trust_lists.py` fetched through
`pki::parse_rca_ctl`/`parse_crl` and `pki::apply` (the fetch itself is the
application's transport). c-its' `c-its-download-int-certs` is the
independent consumer: with `ctl/root-<HASHEDID8>.oer` and a
`root-<HASHEDID8>.json` naming the DC it fetches, validates and extracts the
AA certificates (retained run: `docs/idf/evidence/trust-lists-01`).

### Enrolment and authorization on localhost (EA/AA)

TS 102 941 V2.2.1 clause 6.2.3: an EC from the EA, then an AT from the AA
(which validates the EC's entitlement with the EA). `pki.hpp` builds and
parses every message; the HTTP transport between two separate processes is
the test tools' job, the same division of labour as the DC above:

```sh
vidf_issue root      --key root.pem --name "lab root" --id ROOT --out chain
vidf_issue authority --issuer chain/ROOT.oer --issuer-key root.pem --name "lab EA" --id EA --out chain
vidf_issue authority --issuer chain/ROOT.oer --issuer-key root.pem --name "lab AA" --id AA --out chain
# authority also writes <id>.ekey: the ECIES private key needed to decrypt real requests

python3 ports/esp_idf/tools/local_pki.py --issue-tool build/vidf_issue \
    --ea chain/EA.oer --ea-key chain/EA.vkey --ea-enc-key chain/EA.ekey --canonical-key canonical.pem \
    --aa chain/AA.oer --aa-key chain/AA.vkey --aa-enc-key chain/AA.ekey \
    --dir issued --port 8090          # POST /ea/enrolment, POST /aa/authorization

python3 ports/esp_idf/tools/pki_client.py --issue-tool build/vidf_issue --pki http://127.0.0.1:8090/ enrol \
    --ea chain/EA.oer --canonical-key canonical.pem --its-id my-station --out EC.oer --out-key EC.vkey
python3 ports/esp_idf/tools/pki_client.py --issue-tool build/vidf_issue --pki http://127.0.0.1:8090/ authorize \
    --ea chain/EA.oer --aa chain/AA.oer --ec EC.oer --ec-key EC.vkey --out AT.oer --out-key AT.vkey

vidf_issue verify EC.oer chain/EA.oer chain/ROOT.oer
vidf_issue verify AT.oer chain/AA.oer chain/ROOT.oer
```

`--canonical-key` on both the client and `local_pki.py`/`ea-respond` side is
the same private key file: a lab stand-in for the manufacturer's out-of-band
canonical-key registry a real EA consults, not something this tool invents.
`ea-respond`/`aa-respond` are a lab authority (decrypt, verify, issue, sign,
encrypt with the same building blocks the ITS-S side already uses), not a
production PKI: no replay protection, no butterfly keys, no revocation.
Retained run: `docs/idf/evidence/enrolment-authorization-01`.

### Independent verification of signed frames

`ports/esp_idf/tools/capture_pcap.py` drives `vidf_sut` with such a pool,
triggers the CAM and DENM carriers and writes the transmissions as an IEEE
802.11 pcap (linktype 105, wildcard BSSID, LLC/SNAP 0x8947). Any verifier that
reads pcaps can then judge them; the retained run uses c-its
(https://github.com/TheEnbyperor/c-its, `c-its-pcap`, roots as
`./ctl/root-*.oer`, AAs as `./ctl/aa-*.oer`):

```sh
python3 ports/esp_idf/tools/capture_pcap.py --sut ./build-host/vidf_sut --pool chain \
  --root ROOT --aa AA --at AT --out sut.pcap
mkdir ctl && cp chain/ROOT.oer ctl/root-ROOT.oer && cp chain/AA.oer ctl/aa-AA.oer
RUST_LOG=info c-its-pcap sut.pcap          # one JSON line per frame: signature, chain, security_authorized
```

The same from an ESP32-C5 running the test application: pack the chain into a
credential bundle (`vanetza_idf/credentials.hpp` format, keys in the clear:
keep the file like the keys) and let the capture provision the board over the
USB serial diagnostic channel (command 9) before it resets and signs:

```sh
python3 ports/esp_idf/tools/credential_bundle.py build --pool chain --root ROOT --aa AA --at AT --out chain.vcr
python3 ports/esp_idf/tools/capture_pcap.py --port COM11 --bundle chain.vcr --out device.pcap
```

`vidf_sut --security-bundle chain.vcr` (or `capture_pcap.py --sut ... --bundle`)
takes the same bundle on the host; `serial_sut.py --bundle chain.vcr` provisions
a device before relaying an ETSI campaign's commands. The device keeps the
bundle in RAM for the session; persisting it is the application's
`CredentialStore` (the component tests exercise the NVS store).

Retained in `docs/idf/evidence/independent-verifier-01` (analysis there): with
a ticket carrying CAM, DENM and VRU permissions c-its reports the message
signature, the chain to the root and the CAM/DENM authorisation as valid; with
the standard ticket that also lists psid 141 without an SSP, c-its verifies
every signature but does not validate the permissions because it treats an
omitted SSP as unsupported (its limitation, not a standard's requirement).
`independent-verifier-02` repeats the run under a twin of a real EU CCMS L0
root (`root --like`), i.e. with the CPOC permission profile and the EU
identified region.

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
receiver sensitivity, EIRP, congestion control behavior or complete ITS-G5
compliance. Spectral mask and carrier frequency accuracy are covered
separately by the SYS-RF-001 characterization campaign
(`experiments/evidence/c5-radio-characterization` in the thesis workspace,
HackRF One/PortaPack against ETSI EN 302 571 V2.1.1 clause 4.2.1 and Table 6):
carrier frequency offset is generally within the +-20 ppm limit, but the
transmitted spectral mask fails Table 6 in every tested bench configuration
and MCS rate (0/22 captures per run across three configurations) — this is
disclosed as a measured non-conformance, not a passing result.
