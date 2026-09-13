# vanetza-idf

Modular C++17 Vanetza library for ESP-IDF. Choose an access, network/transport,
or facilities-codec profile; supply your own platform and radio adapters.
The portable core targets the ESP32 family. The integrated C5 radio backend
is experimental and requires separate hardware validation.

**Start with the [ESP-IDF integration guide](docs/idf/README.md).** It covers
installation, Kconfig, ownership/event-loop rules, examples, and standalone
host/device tests. [Standards traceability](docs/idf/standards.md) links the public
interfaces to precise ETSI editions and clauses.
The [interface assessment](docs/idf/interface-assessment.md) identifies remaining
contract and capability gaps. [Test campaigns](docs/idf/test-campaigns.md) explains
how the separately installed ETSI framework and two-C5 radio tests connect.

**This is an experimental port, not a completed ETSI-conformant stack.**
See [implementation and conformance gaps](docs/idf/conformance.md) and
[validation results](docs/idf/validation.md). CAM/DENM/VAM codecs and endpoints
are distinct from complete Basic Services.

## Components and configurable boundaries

The arrangement follows the facilities, networking/transport and access layers
of the ETSI ITS station architecture, with management and security alongside
them. It is an implementation map, inspired by
[TS 102 723-11, clauses 4–5](https://www.etsi.org/deliver/etsi_ts/102700_102799/10272311/01.01.01_60/ts_10272311v010101p.pdf)
and [EN 303 797, Annex B](https://www.etsi.org/deliver/etsi_en/303700_303799/303797/02.01.01_60/en_303797v020101p.pdf).
It does not imply that every service in those figures is implemented.

```mermaid
flowchart TB
    application["Application or upper tester"]
    subgraph station["vanetza-idf"]
        direction LR
        management["Management inputs: position, clock, MIB and configuration"]
        subgraph layers["Selectable protocol components"]
            direction TB
            subgraph facilities["Facilities profile"]
                direction LR
                cam["CAM Release 2 codec"]
                denm["DENM Release 2 codec"]
                vam["VAM Release 2 codec"]
                services["CA, DEN and VRU Basic Services: pending"]
            end
            btp["Network profile: BTP-A and BTP-B"]
            gn["GeoNetworking router: SHB and GBC; Release 2 gaps remain"]
            access["Access profile: AL_DATA boundary and parameter validation"]
            cam --> btp
            denm --> btp
            vam --> btp
            btp --> gn
            gn --> access
        end
        security["Security entity: TS 103 097 signing, ticket pool, identifier change; verification pending"]
        saps["Cross-layer SAP bindings: SN, SF, MN, MF, MI"]
        management -.-> gn
        security -.-> gn
        saps -.-> security
        saps -.-> gn
    end
    application -->|"Facilities PDU entry"| facilities
    application -->|"BTP-DATA entry"| btp
    application -->|"AL_DATA entry"| access
    access <-->|"Owned GNPDU and metadata"| adapter["External Access adapter: software lower tester or radio"]
    adapter -.-> radio["ESP32-C5 radio: experimental implementation; DCC and hardware validation pending"]
    etsi["Separately installed ETSI TTCN-3 framework and SUT adapter"] -.-> application
    etsi -.-> adapter
    hil["Optional HIL framing: bounded VID1 transport envelope"] -.-> etsi
    classDef available fill:#e6f4ea,stroke:#237a3b,color:#17251b
    classDef external fill:#e8f0fe,stroke:#4169a1,stroke-dasharray:5 4,color:#182439
    classDef pending fill:#fff3cd,stroke:#9b7110,stroke-dasharray:5 4,color:#392c0a
    class cam,denm,vam,btp,gn,access,management,hil,saps available
    class application,adapter,etsi external
    class services,security,radio pending
```

Green denotes available code, blue denotes application/test infrastructure,
and amber denotes incomplete functionality. Dashed connections describe
integration relationships. Reception travels back up the selected layers;
the diagram emphasizes transmit entry points. The access profile omits the
network and facilities layers; the network profile adds BTP/GeoNetworking;
the facilities profile also enables the individually selectable codecs.
The optional HIL envelope carries adapter payloads; it is not an ETSI protocol.

## External TTCN-3 and HIL

Install the TTCN-3 runtime and the [official ETSI ITS framework](https://forge.etsi.org/rep/ITS/TS.ITS)
separately. The library does not install or bundle them. The test application
connects that framework's suite-specific SUT adapter to these points:

| Point | API/boundary | Intended use |
|---|---|---|
| Upper tester | Named NF-SAP binding, `Stack::request`, position/time/security injection | Stimulate implemented behavior and collect actual results; full service operations remain pending |
| Software lower tester | `Access::request` and `Stack::indicate` | Inject/observe GN traffic while the protocol implementation runs on the ESP32 |
| Physical lower tester | Independent ITS-G5 capture/injection radio | Validate transmitted frames, access behavior and RF properties |

Enable `CONFIG_VANETZA_IDF_HIL` for optional bounded framing. USB/UART/BLE/IP
transports and suite-specific command decoding remain in the test application
and host SUT adapter. Preserve the ETSI codec payload and map it to the actual
service under test; never synthesize a successful acknowledgement.

The [hook-up guide](docs/idf/README.md#connect-a-separately-installed-etsi-ttcn-3-framework)
explains payload boundaries, metadata, real-time versus injected-time tests,
PICS/PIXIT, Release 2 ATS adaptation, and evidence retention. A mirrored SUT
packet is software evidence; radio conformance requires independent observation.

## Foundation and acknowledgements

vanetza-idf is an independent ESP-IDF adaptation built on
[Vanetza](https://github.com/riebl/vanetza). It is not maintained by, affiliated
with, or endorsed by the Vanetza team. Upstream authorship and license notices
remain with the original source files. See the
[upstream documentation](https://www.vanetza.org/) for the original library.

Thank you to [OpenTrafficMap](https://codeberg.org/opentrafficmap) for the
foundational work that established how to transmit ITS-G5 using the ESP32-C5
radio, shared in their
[receiver firmware with TX enabled](https://codeberg.org/opentrafficmap/its-g5-receiver-firmware_txenabled).
The C5 backend builds on that work. Its private SDK dependencies and validation
status are documented separately from the portable protocol core.

Vanetza is licensed under LGPLv3; see [LICENSE.md](LICENSE.md).
Third-party components retain their respective notices and licensing terms.
