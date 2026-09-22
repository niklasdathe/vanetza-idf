# enrolment-authorization-01: EA/AA enrolment and authorization over HTTP on localhost

TS 102 941 V2.2.1 clause 6.2.3: an ITS-S obtains an enrolment credential (EC) from
its EA and, using that EC, an authorization ticket (AT) from an AA that in turn
validates the EC's entitlement with the EA ("AA <-> AA" of the security
architecture's Online PKI roles box). `vanetza_idf::pki` already built and parsed
every message in-process (`test_pki.cpp`); nothing carried the bytes between two
separate processes over a real transport, which is exactly the transport half of
GAP-PKI-001 (`docs/idf/conformance.md`). Here the lab EA and AA run as a real
localhost HTTP server (`tools/local_pki.py`) and a lab station drives the whole
enrol-then-authorize sequence against it as a real client (`tools/pki_client.py`),
both shelling out to `vidf_issue`'s new `enrol-*`/`authorize-*`/`ea-respond`/
`aa-respond` subcommands for the actual TS 102 941 cryptography.

Closing the transport also surfaced two bugs that never mattered while the EA/AA
side only ran in-process against keys the same test already knew:

- `TrustDomain::issue_authority` generated a fresh ECIES encryption key for every
  EA/AA certificate and embedded the public half, but discarded the private half
  --  every EA/AA `vidf_issue` ever produced could never actually decrypt a real
  request. Fixed by returning it through an out-param, persisted as `<id>.ekey`.
- The library's `copy_curve_point` (reading a wire verification key back out of a
  certificate) leaves `.y` empty for the compressed form the wire always uses,
  recording only the parity. Code that takes such a key and blindly copies `.x`/`.y`
  into a new certificate (as issuing one for a station's *requested* key must)
  silently embeds the wrong point about half the time. Fixed in the new
  authority-side `public_key_of` by decompressing (`vanetza_idf::ecc::decompress`)
  before the key is used to issue anything.

| File | Content |
| --- | --- |
| `ROOT.oer` | throwaway lab root, `vidf_issue root` |
| `EA.oer` | EA under the root, `vidf_issue authority` (with `.ekey` alongside, not copied here) |
| `AA.oer` | AA under the root, `vidf_issue authority` |
| `EC.oer` | the enrolment credential `ea-respond` issued for the station's requested key |
| `AT.oer` | the authorization ticket `aa-respond` issued after validating `EC.oer`'s entitlement with the EA |
| `server.log` | `local_pki.py`'s log of the two requests it served |

## Commands

```
vidf_issue root      --key root.pem --name "demo root" --id ROOT --out chain
vidf_issue authority --issuer chain/ROOT.oer --issuer-key root.pem --name "demo EA" --id EA --out chain
vidf_issue authority --issuer chain/ROOT.oer --issuer-key root.pem --name "demo AA" --id AA --out chain

python tools/local_pki.py --issue-tool build/vidf_issue \
    --ea chain/EA.oer --ea-key chain/EA.vkey --ea-enc-key chain/EA.ekey --canonical-key canonical.pem \
    --aa chain/AA.oer --aa-key chain/AA.vkey --aa-enc-key chain/AA.ekey \
    --dir issued --port 8092

python tools/pki_client.py --issue-tool build/vidf_issue --pki http://127.0.0.1:8092/ enrol \
    --ea chain/EA.oer --canonical-key canonical.pem --its-id vidf-http-demo \
    --out EC.oer --out-key EC.vkey
python tools/pki_client.py --issue-tool build/vidf_issue --pki http://127.0.0.1:8092/ authorize \
    --ea chain/EA.oer --aa chain/AA.oer --ec EC.oer --ec-key EC.vkey \
    --out AT.oer --out-key AT.vkey

vidf_issue verify EC.oer chain/EA.oer chain/ROOT.oer   # chain verifies
vidf_issue verify AT.oer chain/AA.oer chain/ROOT.oer   # chain verifies
```

A tampered `EnrolmentRequest` (one octet flipped) fed to `ea-respond` directly is
refused: "request did not decrypt/verify/decode; nothing was issued", exit 1 --
`local_pki.py` turns that into HTTP 400 rather than fabricating a response.

## Result

- Both HTTP round trips completed (`server.log`: two `POST ... 200`), and both
  resulting certificates verify their full chain to the same lab root
  (`vidf_issue verify`, signature + validity + region + permission-consistency
  checks, IEEE Std 1609.2 clause 5.1.2).
- The AA's entitlement check of the EC (`aa-respond` internally calling the new
  `validate_entitlement`, decrypting the EC's forwarded signature with the EA's
  key and checking it against the `SharedAtRequest` hash, clause 6.2.3.3.1)
  succeeded against the real `EC.oer` this run actually issued -- not a
  same-process fixture the test already trusted.
- `vidf_tests` (929 checks) is unaffected: `test_pki.cpp` was refactored to call
  the same shared `pki_authority` parsing/response code this evidence exercises
  operationally, rather than duplicating it inline.

## Scope

This closes the ad hoc/manual-testing half of GAP-PKI-001: a real HTTP transport
for enrolment and authorization now exists and is proven correct end to end. It
does not run the official ETSI `AtsPki` suite (163 cases, still 0 executed) --
that needs the licensed/compiled test-system binary and a TTCN upper-tester
adapter (the `build_etsi_btp_adapter.py`/`etsi_btp_adapter.cpp` pattern), a
separate effort. Nor does it implement the phone's own TS 102 941 client
(`architecture/diagrams/microbu-architecture-2b-revision-b-security.drawio`):
today's flow is lab tooling standing in for both the EA/AA and the requesting
station, not new C5/phone firmware.
