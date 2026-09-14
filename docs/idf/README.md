# vanetza-idf

A configurable C++17 [Vanetza](https://github.com/riebl/vanetza) library for ESP-IDF,
with portable access, network/transport, facilities codec and test boundaries.
The component does not own a FreeRTOS task or start a radio. Applications supply
time, position, security and access implementations.

**Status: experimental port, not an ETSI-conformant complete station.** The
Release 2 interface bindings and CAM/DENM/VAM codecs are implemented. The
upstream router provides SHB and GeoBroadcast; complete Release 2 GN, CA/DEN/VRU
Basic Service behavior, a production security entity and a validated C5 radio
remain work items. [Conformance status](conformance.md) records these precisely.
Selecting a codec does not implement the associated Basic Service.

## Integrate in an ESP-IDF project

Install ESP-IDF separately, then clone this repository recursively inside your
project's `components` directory. Keep the directory name `vanetza-idf`:

```sh
git clone --recurse-submodules https://github.com/niklasdathe/vanetza-idf.git components/vanetza-idf
```

`master` carries the port without the security entity. The security entity,
identifier change, cross-layer SAP bindings and TS 102 941 core live on
`feature/etsi-cross-layer-security` (add `--branch feature/etsi-cross-layer-security`)
and stay there until sending signed messages with real credentials has been
verified end to end; see [validation.md](validation.md). Pin a reviewed commit
for reproducible builds. An existing clone needs
`git submodule update --init --recursive`.

Alternatively, keep the clone elsewhere and add its absolute path to
`EXTRA_COMPONENT_DIRS` **before** including ESP-IDF's `project.cmake`:

```cmake
cmake_minimum_required(VERSION 3.22)
list(APPEND EXTRA_COMPONENT_DIRS "/path/to/vanetza-idf")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(my_its_application)
```

The consumer component declares its dependency normally:

```cmake
idf_component_register(SRCS "main.cpp" REQUIRES vanetza-idf)
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)
```

Set these in the application's `sdkconfig.defaults`, then select the profile in
`idf.py menuconfig` → **Component config → Vanetza-IDF**:

```ini
CONFIG_COMPILER_CXX_EXCEPTIONS=y
CONFIG_COMPILER_CXX_RTTI=y
CONFIG_ESP_MAIN_TASK_STACK_SIZE=32768
CONFIG_VANETZA_IDF_PROFILE_NETWORK=y
```

The component manifest resolves `espressif/esp-boost` 0.4.1. Git submodules pin
the additional Boost headers that package omits. No source-generation tool,
TTCN compiler, workstation path or host test framework is required to build
the device library. ESP-IDF >=5.3 is the declared dependency floor; only builds
listed in [validation](validation.md) have actually been checked.

## Choose the entry point

| Profile | Feed in | Built functionality | Main API |
|---|---|---|---|
| `ACCESS` | GNPDU plus radio parameters | IN-SAP binding and access utilities | `AccessStack::request(AlDataRequest)` |
| `NETWORK` | Facilities bytes plus BTP/GN parameters | BTP, upstream GN router and its dependencies | `Stack::request(BtpRequest)` |
| `FACILITIES` | Release 2 CAM, DENM or VAM PDUs | Network profile and independently selected codecs | `facilities::send`, typed `Cam`/`Denm`/`Vam` |

`CONFIG_VANETZA_IDF_CAM`, `..._DENM` and `..._VAM` control individual codecs.
The source manifest includes only the ASN.1 types transitively needed by enabled
services. `CONFIG_VANETZA_IDF_HIL` adds transport-independent tester framing;
it defaults off. `CONFIG_VANETZA_IDF_SECURITY` (default on with the network
profile) builds the signing security entity, the PSA crypto backend and the
identifier change; `CONFIG_VANETZA_IDF_SECURITY_VERIFY` (default on) adds the
verification of received secured packets; `CONFIG_VANETZA_IDF_PKI`
(default off) adds the TS 102 941 request/response core. Optional features are
removed at compile time, rather than being permanently allocated and merely
ignored at runtime.

The core has no target-specific headers. It is intended for any ESP32 supported
by the selected ESP-IDF/toolchain with sufficient memory. A C5 radio backend is
a separate, target-specific adapter; another ESP32 can use an external radio or
a test lower port. Building on an ESP32 does not establish ITS-G5 PHY support.

## Supply an access adapter

Implement `vanetza_idf::Access::request(AlDataRequest)`. This method owns its
argument. Preserve source/destination MAC, priority, power, MCS, bandwidth,
channel, transceiver/mode and datastream ID. Reject an unsupported control
explicitly; silently changing it makes interface testing meaningless.

`AlDataRequest::data` starts at the **GeoNetworking Basic Header**. The adapter
adds/removes LLC/SNAP, MAC and PHY encapsulation, and enforces the selected
access/DCC behavior. A request result means acceptance/rejection by the local
adapter, not proof of radio transmission. Missing CBR/RSSI observations are
represented as absent measurements, never invented zeros.

```cpp
#include <vanetza_idf/access.hpp>

class Radio : public vanetza_idf::Access {
public:
    vanetza_idf::Result request(vanetza_idf::AlDataRequest request) override {
        // Validate hardware controls and transfer ownership to your driver queue.
        return vanetza_idf::Result::unsupported; // replace with a real driver
    }
};
```

This binding follows EN 303 797 Annex B.2. It is a local C++ representation of
the illustrated service primitives, **not** an ETSI-defined binary ABI. In
particular, neither a C++ object layout nor raw structs should be sent over BLE,
SPI or USB. Define an explicit versioned serialization for an inter-device link.

## Security entity and identity management

`vanetza_idf/security.hpp` provides a signing security entity for the SN-SAP
(TS 102 723-8) that the GeoNetworking router calls for every outgoing packet
when `itsGnSecurity` is set. The application provisions it; nothing is built
in:

```cpp
using namespace vanetza_idf::security;
vanetza_idf::BackendMbedTls backend;          // PSA Crypto (host: vanetza::security::BackendOpenSsl)
TrustConfiguration trust;                     // root CA and the AA(s) of the tickets, COER
trust.add_root(root_coer); trust.add_authority(aa_coer);
CertificatePool pool {backend};               // authorization tickets with their private keys
pool.add(at_coer, at_private_key);            // TS 103 097 clause 7.2.1 profile checked, key probed
SecurityEntity entity {runtime, position_provider, backend, pool, trust};
Stack stack {config, runtime, access, &entity};
```

The entity applies the TS 103 097 V2.2.1 signing profiles by ITS-AID and the
SN-ENCAP `context_information`: CAM (clause 7.1.1: digest, certificate once
per second or when a new CAM signer was reported), DENM (clause 7.1.2:
certificate, generationLocation), generic/GN-MGMT (clause 7.1.3), VAM
(TS 103 300-3 clause 6.5: individual 1 s, cluster 500 ms through
`context::vam_cluster`). Without a valid ticket for the requested ITS-AID and
permissions, or without an anchored chain, the request is refused and counted
(`SecurityEntity::statistics()`); nothing is transmitted unsigned.

SN-DECAP verifies received `EtsiTs103097Data-Signed` packets (IEEE Std 1609.2
clause 5.2 as TS 103 097 clause 5.2 requires): the TS 103 097 clause 7.1
structure for the ITS-AID, the signer (inline certificate or a digest learned
earlier), the ticket's validity, permissions and region, every certificate
signature up to a provisioned root, the message signature, then the
generationTime window and replay detection of `VerificationPolicy`
(`set_verification_policy`). A CAM from an unknown station or with an unknown
AA triggers the P2P certificate distribution of clause 7.1.1 through the header
policy, and an AA received in `requestedCertificate` is learned once it chains
to a root. The GN router drops what does not verify (`itsGnSnDecapResultHandling`
STRICT) and passes report, ITS-AID and SSP of what does up to BTP. Without
`CONFIG_VANETZA_IDF_SECURITY_VERIFY` the report is `Configuration_Problem` and
nothing secured is passed up (docs/idf/conformance.md GAP-SEC-001). Revocation
(CRL/CTL) and encryption are not implemented; identified regions (country
codes) are accepted unless the application supplies a geodesy country
database. Budget on the ESP32-C5: about 34 ms per verified message, 29 ms of
which is the ECDSA peripheral (validation.md).

`IdentityManager` implements the identifier change of TS 102 723-8 clause 6.3:
subscribers (the GN core when `itsGnLocalAddrConfMethod` is ANONYMOUS, the
facilities layer through `sf_sap.hpp`, any other layer through `sn_sap.hpp`)
receive PREPARE, answer through the responder, then COMMIT with the HashedId8 of
the next ticket or ABORT; ID-LOCK holds the identifier for 0..255 s. A
subscriber may run in the same task, in another task or process, or on another
device; the responder object may be answered later from anywhere. The library
defines no transport for that and no policy for *when* to change: the
application triggers, the manager sequences.

The private keys of the tickets stay with the application: the pool holds
them, the backend imports them as volatile PSA keys, and no key ever leaves the
device through this library. The test trust domain of the component tests
(`tests/test_trust_domain.*`, `vidf_test_pool`) is generated per run and is not
a PKI.

## Cross-layer SAPs

The management and security SAPs of the ITS station are bound as plain C++
types and `*_request_submit` functions, one header per SAP, each declaration
commented with its standard, edition and clause:

| Header | SAP | Serves |
|---|---|---|
| `sn_sap.hpp` | SN-SAP, TS 102 723-8 V2.0.0 (V1.1.1 Tables 10 to 27) | SN-ENCAP/-DECAP into the security entity; SN-IDCHANGE-*/SN-ID-LOCK into the identity manager |
| `sf_sap.hpp` | SF-SAP, TS 102 723-9 V1.1.1 | The same identity manager for the facilities layer (clause 4.1.5); SF-SIGN/-VERIFY/-ENCAP/-DECAP as types only |
| `mn_sap.hpp` | MN-SAP, TS 102 723-4; TS 103 836-4-1 Annex K; TS 103 175 clause 8.3 | `CORE_MMT_response_apply` (time, position, address, TC mapping) into the stack; DCC N-Params through the application's provider |
| `mf_sap.hpp` | MF-SAP, TS 102 723-5 V2.0.0; TS 103 175 clause 8.4 | DCC F-Params into the application's facilities layer |
| `mi_sap.hpp` | MI-SAP, TS 102 723-3; TS 103 175 clause 8.2 | DCC I-Params through the application's access adapter |

The peer of each binding (management entity, facilities layer, access adapter,
identifier-change subscriber) may live in the same task, another task or
process, or another device. The library defines no transport, serialization or
RPC for these primitives, invents no DCC measurement (an absent provider
answers ErrStatus 250, an undefined command ErrStatus 5 per TS 102 723-3 clause
5.2.3) and keeps every optional peer compile-time selectable. The default build
is one un-split station.

## Own the stack from one event loop

```cpp
#include <vanetza_idf/stack.hpp>

vanetza::ManualRuntime time;
vanetza_idf::StackConfig config;
// Configure GN identity, radio controls and the MIB before construction.
// Supply a security::SecurityEntity when itsGnSecurity is true (the default).
vanetza_idf::Stack stack(config, time, radio, security_entity);

stack.on_receive([](vanetza_idf::BtpIndication indication) {
    // Dispatch the owned facilities payload by destination_port and BTP type.
});
stack.on_access_result([](vanetza_idf::Result result) {
    // Record actual lower-adapter acceptance/failure, including later forwarding.
});
```

Keep `time`, `radio` and the security entity alive until after stack destruction.
Advance time, inject position, call request/indicate and destroy the stack from
the **same application task**. ISRs and other tasks enqueue events to that task.
Do not re-enter the stack from callbacks. No global singleton is required;
independent stacks can coexist.

Supply a coherent position with `update_position(PositionFix)` and an ITS epoch
clock via `advance(Clock::time_point)`. Upstream `Clock` counts microseconds from
2004-01-01; `esp_timer_get_time()` alone is uptime, not ITS time. The application
must maintain the absolute-time mapping and uncertainty. Regressing time is
rejected. Reinitialize an instance when an epoch reset is required.

For BTP, port values are in host byte order; the library serializes them in
network byte order. BTP-A requires a source port and excludes destination port
info; BTP-B excludes a source port. Optional GN parameters inherit the configured
MIB. Unsupported GN transports return `Result::unsupported`, never silently
become a different transport. `accepted` means submitted for protocol processing;
it is not a promise of RF delivery.

## Build and test the standalone examples

```sh
cd examples/esp_idf
idf.py set-target esp32c5
idf.py build
```

Use `esp32`, `esp32s3`, or another SDK target for the same portable example.
`sdkconfig.access` and `sdkconfig.network` are alternative profile overrides.
Supply overrides using `SDKCONFIG_DEFAULTS` with a **fresh sdkconfig/build
directory**; changing defaults does not rewrite an existing sdkconfig. The
example deliberately uses a rejecting access adapter and emits no RF traffic.

`examples/esp_idf_test` runs the same component regression code on a device.
Select the correct target and port before `idf.py flash monitor`. Retain
`VIDF_TEST_RESULT=0`, firmware hash, target, SDK version and configuration.
These are component tests, not TTCN verdicts or radio-conformance evidence.

On a host with CMake, a C++17 compiler and Boost development headers:

```sh
cmake -S ports/esp_idf -B build-host -DVIDF_TESTS=ON
cmake --build build-host
ctest --test-dir build-host --output-on-failure
```

Host configuration uses `VIDF_NETWORK`, `VIDF_CAM`, `VIDF_DENM`, `VIDF_VAM` and
`VIDF_HIL` with the same meaning as the device features. Build with all four
network/facilities features off to test the access-only configuration.

## Connect a separately installed ETSI TTCN-3 framework

**The user installs and configures TTCN-3, its runtime, the ETSI ATS, codecs,
platform adapter and SUT adapter separately.** This repository neither installs
nor vendors that framework. Start from the official
[ETSI ITS Test Suite](https://forge.etsi.org/rep/ITS/TS.ITS) and its suite-specific
instructions. Choose and record immutable revisions and the associated published
ATS, TSS/TP, PICS and PIXIT editions.

The test architecture is:

```text
ETSI TTCN-3 ATS + codecs + platform/SUT adapter (host)
  | upper tester: suite-specific commands and real result/event indications
  | optional USB/UART/Ethernet transport, supplied by the test application
  v
test application on ESP32 -> service/BTP/position/security hooks -> stack
                                                               |
                                  lower tester <-> Access adapter
                                         or independent ITS-G5 test radio
```

| Test point | Connect to | Intended use |
|---|---|---|
| Facilities upper tester | Actual CA/DEN/VRU service trigger, update, termination, position and pseudonym operations | Test generation rules, timers and service state; it must invoke the service under test, not prebuild the expected PDU |
| BTP upper tester | `Stack::request(BtpRequest)`; result/events from the actual operation and `on_receive` | Test BTP-A/B headers, payload delivery and port handling |
| GN upper tester | Router request/configuration through the test application | Test supported GN transports, forwarding and lifetimes; unsupported transports remain explicitly unimplemented |
| Position/time control | `Stack::update_position` and `Stack::advance` | Deterministic host/component tests; physical campaigns use measured real time and ATS-defined timing tolerances |
| Security | Injected `SecurityEntity`, real credentials and trust configuration; `vidf_sut --security-pool` for the host | Test signing and authorization (`etsi_security_gn.cfg`, `etsi_security_facilities.cfg`) and reception (`etsi_security_receive.cfg`: the test system signs in TTCN-3, the adapter reports what the SUT passes up); an absent signer cannot produce success |
| Software lower tester | `Access::request` (outgoing GNPDU), `Stack::indicate` (incoming GNPDU and metadata) | HIL for BTP/GN on the MCU while bypassing RF; codec conversion must preserve the ATS lower-port semantics |
| Physical lower tester | Independent ITS-G5 capture/injection radio | Test MAC/PHY, channel behavior, radiated packets and integrated ITS-G5 behavior |

`hil::Decoder`/`hil::encode` offer an optional bounded envelope:
`VID1 | channel:u8 | sequence:u32be | length:u16be | payload | CRC32:u32be`.
Channel 1 carries upper tester bytes, channel 2 lower tester data, and channel 3
diagnostics. This framing is a **library transport choice**, not an ETSI wire
protocol. The host SUT adapter or bridge adds/removes it. Match the suite's own
UT codec revision and command layout; no universal UT opcode table is assumed.

The `hil::UpperTester` callback accepts raw suite-specific UT payload and may
return a real encoded result. A missing handler or unsupported command must not
produce a success response. Sequence numbers correlate request/results;
asynchronous events need a separately defined convention in your SUT adapter.
The transport itself does not determine PASS, FAIL, INCONC or ERROR.

The official BTP and GN test ports may contain separate lower-layer encodings
and metadata; raw GNPDU bytes are not automatically their complete wire format.
Implement that conversion in the host SUT adapter and verify it independently.
Example ETSI adapter sources to inspect are `UpperTester` codecs under
`ccsrc/Protocols` and the selected ATS `lib_system` test ports.

For Release 2, do not simply relabel an older ATS. Check each TP's referenced
clause, ASN.1/CDD version, PICS option, template and UT encoding. Keep any
adaptation in an auditable overlay in the **external test project**, retain the
original case identity and record added/changed coverage. Keep official,
adapted and component-test verdicts distinct. Record absent test coverage.

For each campaign retain: firmware/source hashes, sdkconfig, SDK/compiler and
target, ATS/runtime/adapter revisions, PICS/PIXIT, case list, verdicts, complete
logs, packet captures, clock calibration and the actual upper/lower boundaries.
A SUT's mirrored outgoing bytes establish software behavior, not independent RF
transmission. Do not change production protocol behavior merely to satisfy UT.

## Design and standards references

- [Standards and interface traceability](standards.md)
- [Conformance and implementation gaps](conformance.md)
- [Build and test evidence](validation.md)
- [Source manifest](../../ports/esp_idf/source-manifest.json)
- [Upstream and dependency licenses](../../LICENSE.md)

The fork retains upstream history and notices. Only selected sources enter the
IDF component. Upstream host tools, cellular/IPv6 application paths, RPC, PQC,
PKI clients, infrastructure and collective-perception services are outside the
embedded profile. The repository keeps upstream sources to support merging;
source presence does not mean the component compiles or links those modules.
