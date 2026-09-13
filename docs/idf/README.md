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

Until the port branch is merged, add `--branch codex/esp-idf-library` to that
command. Pin a reviewed commit for reproducible builds. An existing clone needs
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
it defaults off. Optional features are removed at compile time, rather than
being permanently allocated and merely ignored at runtime.

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
| Security | Injected `SecurityEntity`, real credentials and trust configuration | Test signing/verification and authorization; an absent signer cannot produce success |
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
