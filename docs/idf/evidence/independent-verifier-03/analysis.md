# independent-verifier-03: the ESP32-C5 signs with credentials provisioned at run time

The board (COM11, test application `examples/esp_idf_test`, image of
[security-device-08](../security-device-08/result.json)) receives the twin chain
of [independent-verifier-02](../independent-verifier-02/analysis.md) as a
credential bundle over its USB serial diagnostic channel (command 9,
`credentials.hpp` format), resets into the secured profile, signs the CAM
carriers, and c-its verifies the recorded frames against the twin root.

| File | Content |
| --- | --- |
| `device.pcap` | three CAMs signed by the board with `TWIN_AT` (psid 638, 141, 36; region inherited) |
| `device2.pcap` | the same with `TWIN_AT2` (without psid 141) |
| `host-bundle.pcap` | the host SUT provisioned from the same bundle file (`vidf_sut --security-bundle`), for comparison |
| `c-its-*.jsonl` | c-its-pcap output per capture |

The bundle files are not retained: they carry the tickets' private scalars
(the twin chain's public certificates are in -02).

## Commands

```
credential_bundle.py build --pool twin --root TWIN_RCA --aa TWIN_AA --at TWIN_AT  --out twin.vcr
credential_bundle.py build --pool twin --root TWIN_RCA --aa TWIN_AA --at TWIN_AT2 --out twin2.vcr
capture_pcap.py --port COM11 --bundle twin.vcr  --out device.pcap
capture_pcap.py --port COM11 --bundle twin2.vcr --out device2.pcap
capture_pcap.py --sut vidf_sut --bundle twin.vcr --out host-bundle.pcap
c-its-pcap device.pcap / device2.pcap / host-bundle.pcap   (ctl/root-TWIN_RCA.oer, ctl/aa-TWIN_AA.oer)
```

## Result

| Capture | Signer | Message signature | Chain (root, AA, AT) signatures | `security_authorized` |
| --- | --- | --- | --- | --- |
| `device.pcap` | ESP32-C5, PSA Crypto | verifies (3/3) | verify (3/3) | false (psid 141 without SSP, c-its limitation as in -01) |
| `device2.pcap` | ESP32-C5, PSA Crypto | verifies (3/3) | verify (3/3) | **true** (3/3) |
| `host-bundle.pcap` | host, OpenSSL | verifies (3/3) | verify (3/3) | false (psid 141) |

The generation times in `device.pcap` are the board's ITS clock as set by the
capture (command 5) and the pcap timestamps the host's wall clock; c-its checks
them against each other. The DENM carrier produces no frame because the twin
tickets carry no psid 37 (the twin root's DENM range needs SSP version 2).

## What this shows and what not

The run-time provisioning path exists end to end (bundle → diagnostic command
→ `Credentials` → `apply()` → security entity) and the board's signatures are
accepted by an unrelated implementation. It does not show the project root:
the twin has the real root's permissions and region but a throwaway key; the
real chain is issued by the key holder with the same tools. Persistence across
resets is the application's `CredentialStore`; the test application keeps the
bundle in RAM and exercises the NVS store in `test_credentials` only.
