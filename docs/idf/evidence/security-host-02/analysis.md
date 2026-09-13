# security-host-02: AtsSecurity, CAM and DENM profiles (sending side)

Campaign: `ports/esp_idf/tests/etsi_security_facilities.cfg` (7 cases), same
SUT, pool and adapter as `security-host-01` (`adapter-build.json` is the same
link). The test application behind the GN upper tester port emits a CAM
carrier every second (`system.utPort.params := "cam_carrier_ms=1000"`) and a
DENM carrier on `UtDenmTrigger`; both are signed by the SUT's security entity
and verified by the framework against the pool (`enable_security_checks=1`).

| Case | Verdict | Observed |
| --- | --- | --- |
| TC_SEC_ITSS_SND_CAM_01..04_BV | pass | SHB/BTP-B CAM, psid 36, TS 103 097 clause 7.1.1 profile (signer digest, certificate once per second) |
| TC_SEC_ITSS_SND_DENM_01..03_BV | pass | GBC/BTP-B DENM, psid 37, clause 7.1.2 profile (generationLocation present) |

`AtsSecurity.framework-dathe-3.log` is the log of the `DENM Trigger` PTC of the
first DENM case; the two later PTC logs are identical in structure and were not
retained. No CA or DEN basic service is involved: the carriers are syntactically
valid Release 2 PDUs produced by the test application (`hil_sut.cpp`,
commands 7 and 8), which is what the testcases request through the upper
tester ("the IUT is requested to send a secured CAM/DENM").
