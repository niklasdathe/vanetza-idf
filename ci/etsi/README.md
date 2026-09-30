# ETSI TTCN-3 CI

This directory turns the repository's existing external ETSI adapters into a
repeatable GitHub Actions regression campaign. It does **not** claim complete
ETSI conformance.

## Scope

The hosted CI executes the official ETSI testcase objects for the currently
wired software SUT boundaries:

- BTP: 5 selected cases;
- GeoNetworking: the 3 cases reached by the current SHB-source PICS;
- Security sending, GN-MGMT: 8 cases;
- Security sending, CAM/DENM carriers: 7 cases;
- Security receiving: 26 cases.

The testcase objects are taken from the pinned ETSI TS.ITS tree in
`versions.env`. The repository's adapter builders replace only the relevant SUT
test ports. The GeoNetworking codec null-pointer workaround remains a disposable
build overlay; the pinned ETSI checkout is not edited.

## Verdict policy

`ports/esp_idf/tools/run_etsi.py` always records the raw TITAN verdicts and
returns failure if any testcase is non-PASS. CI then evaluates `result.json`
with `check_result.py`.

`expected-outcomes.json` contains the explicit baseline. A known ETSI testcase
defect or an intentional adapter scope gap is therefore still executed on every
run, but does not make CI red while its verdict remains exactly the documented
baseline. Any change, including an unexpected PASS of a baselined upstream
defect, fails the check so the baseline must be reviewed deliberately.

## Reproducibility

`setup_toolchain.sh` builds the pinned TITAN release and checks out the pinned
ETSI TS.ITS revision recursively. GitHub Actions caches the resulting toolchain
by both pins. Test artifacts retain:

- `result.json` from every campaign;
- copied PICS/PIXIT configuration and testcase list;
- TITAN MTC/console logs;
- adapter `build.json` hashes;
- the toolchain manifest and submodule revisions.

Update `versions.env` only as a deliberate validation change. Updating the ETSI
or TITAN pin can legitimately change generated code, testcase behavior, or
framework defects and therefore requires review of the complete campaign.

## Hardware validation

GitHub-hosted runners validate the host SUT only. ESP32-C5 execution, DCC/access
behavior, and independent ITS-G5 observation still require a self-hosted lab
runner with the physical DUT and lower tester. Do not treat a green hosted job
as RF/MAC conformance evidence.
