# security-host-05: AtsSecurity, receiving side

Campaign: `ports/esp_idf/tests/etsi_security_receive.cfg` (26 cases: the compiled
`TC_SEC_ITSS_RCV_*` cases of the pinned suite minus those gated by PICS this SUT
does not claim, i.e. implicit certificates and Brainpool), host SUT `vidf_sut
--security-pool ./certificates` built with `VIDF_SECURITY_VERIFY=ON`, pool from
`vidf_test_pool` (now also `CERT_TS_B_AT`, a ticket restricted to a 5 km circle
around the SUT position, selected as `PX_AT_CERTIFICATE`). The test system signs
in TTCN-3 with `CERT_TS_A_AT`/`CERT_TS_B_AT`; the adapter injects each secured
GN PDU into the SUT and reports what the SUT passes up after SN-DECAP as
`UtGnEventInd` (`rawPayload` = BTP header plus SDU). A BV case passes when the
payload the test system sent is indicated upwards, a BO case when it is not.

| Case | Verdict | Observed |
| --- | --- | --- |
| `TC_SEC_ITSS_RCV_MSG_01_BV`, `CAM_01..03_BV`, `CAM_04_BV_XX` | pass | protocol version 3, certificate signer, digest signer after the certificate, x-only signature, region-restricted ticket with the SUT inside: `UtGnEventInd` seen |
| `TC_SEC_ITSS_RCV_MSG_01_BO`, `MSG_02_BO` | pass | protocol version 2 / 4: discarded (`check_profile`) |
| `TC_SEC_ITSS_RCV_CAM_01..09_BO` | pass | wrong psid, missing/extra header fields, invalid signature algorithm, signer `self`, bad signature: discarded, no `UtGnEventInd` |
| `TC_SEC_ITSS_RCV_DENM_01..07_BO`, `DENM_09_BO` | pass | as above for the DENM profile |
| `TC_SEC_ITSS_RCV_DENM_01_BV`, `DENM_02_BV_XX` | **error** | ATS defect, IUT-independent (below) |

## TC_SEC_ITSS_RCV_DENM_01_BV and TC_SEC_ITSS_RCV_DENM_02_BV_XX

Both testcases read NodeB's position in their variable declaration, before the
configuration function has filled the position table:

```
var LongPosVector v_longPosVectorNodeB := f_getPosition(c_compNodeB); // Use NodeB
...
f_cf01Up();
```

`f_getPosition` returns an unbound `LongPosVector` from the still-empty
`vc_positionTable`, and building the DENM's `generationLocation` from it raises
"Dynamic test case error: Creating a template from an unbound integer value"
(pinned `ItsSecurity_TestCases.ttcn` lines 9293 and 9401) before anything is
sent to the IUT. The DENM BO cases do not use that variable and run normally.
The current upstream head (`forge.etsi.org/rep/ITS/ttcn/ats_sec_ts103096-3`,
`master`, `TC_SEC_ITSS_RCV_DENM_01_BV` at line 8608) has the same order. The
verdicts are retained as recorded; the testcases were not modified. The
receiving DENM profile itself (generationLocation present, certificate signer)
is covered by the eight DENM BO cases and by the library's component test
(`test_verification`, step 10).

## What this campaign does not show

The 99 `TC_SEC_ITSS_RCV_CERT_*` and `TC_SEC_ITSS_RCV_GENMSG_*` cases are
commented out in the pinned suite and therefore not compiled; the certificate
chain rules they would exercise are covered by the library's component tests
(forged ticket, unknown AA, expired ticket, permissions) only. Implicit
certificates and Brainpool curves are outside the SUT's PICS.
