# trust-lists-01: an RCA's CTL and CRL from a distribution centre on localhost

TS 102 941 V2.2.1 clause 6.3: the RCA publishes its certificate trust list
(the EA/AA certificates it has issued, the DC access points) and its
revocation list through a distribution centre; an ITS-S fetches them with
the HTTP GETs of Annex D (`getctl/<HashedId8>`, `getcrl/<HashedId8>`) and
takes them only after verifying the RCA's signature (clause 6.3.6). Here the
lists are issued for the twin root of [independent-verifier-02](../independent-verifier-02/analysis.md)
with `vidf_issue`, served by `tools/local_dc.py`, and consumed by an unrelated
implementation (c-its, `c-its-download-int-certs`) as well as by the
library's own reader.

| File | Content |
| --- | --- |
| `ctl-CAEBC77021CE448E.oer` | RcaCertificateTrustListMessage: FullCtl, sequence 1, one AA entry (`TWIN_AA`, access point `http://127.0.0.1:8080/aa/`), one DC entry (`http://127.0.0.1:8080/` publishing the root), signed with the twin root's key, signer certificate inline, psid 624 |
| `crl-CAEBC77021CE448E.oer` | CertificateRevocationListMessage with no entries, psid 622 |
| `crl-revoking-aa.oer` | the same listing the AA (`3BDF03E5FA6F2006`) as revoked |
| `c-its-consumer.log` | c-its fetching both from the local DC |
| `c-its-aa-3BDF03E5FA6F2006.oer/.json` | the AA certificate and access point c-its extracted from the CTL after validating it |
| `c-its-crl-inner-CAEBC77021CE448E.oer` | the ToBeSignedCrl c-its extracted from the CRL |

## Commands

```
vidf_issue ctl --issuer TWIN_RCA.oer --issuer-key lab-root.pem --aa TWIN_AA.oer=http://127.0.0.1:8080/aa/ \
               --dc http://127.0.0.1:8080/ --sequence 1 --out lists/ctl-CAEBC77021CE448E.oer
vidf_issue crl --issuer TWIN_RCA.oer --issuer-key lab-root.pem --out lists/crl-CAEBC77021CE448E.oer
python tools/local_dc.py --dir lists --port 8080
curl http://127.0.0.1:8080/getctl/CAEBC77021CE448E     # 200, application/x-its-ctl, 842 octets
curl http://127.0.0.1:8080/getcrl/CAEBC77021CE448E     # 200, application/x-its-crl, 437 octets
curl http://127.0.0.1:8080/getctl/CAEBC77021CE448E/3   # 404 (no delta lists kept)
# library side
python tools/fetch_trust_lists.py --dc http://127.0.0.1:8080/ --root TWIN_RCA.oer --out fetched
vidf_issue inspect fetched/ctl-CAEBC77021CE448E.oer --root TWIN_RCA.oer
# independent side: ctl/root-CAEBC77021CE448E.oer + .json {"distribution_centre": "http://127.0.0.1:8080/"}
c-its-download-int-certs
```

## Result

- The library reads its own lists back only under the signing root: `inspect`
  with the lab root of -01 answers "neither a CTL nor a CRL signed by that
  root"; a tampered CTL, a CTL of another root and a CTL carrying an AA the
  root did not issue are refused in `test_trust_lists`; the CRL entry becomes
  a revocation the chain validator honours (`test_chain_consistency`:
  `REVOKED_CERTIFICATE` for every ticket under the revoked AA, verifying again
  once the CRL is replaced).
- c-its fetched the CTL and the CRL from the local DC, validated the CTL as
  signed by the root with CTL permissions (`security_report`: signature
  verifies, chain = the root, `validated_chain_index 0`), wrote the AA
  certificate with its access point and the CRL content.

## Note on the c-its consumer

At commit e3bb3b8 `c-its-download-int-certs` inserts the root into its store
as an ordinary certificate (`insert_cert`) instead of as a trust anchor
(`add_root_ca`), so `validated_chain()` is never satisfied for a root-signed
CTL and every CTL is reported as "not signed with a valid chain". The local
checkout replaces that one call with `add_root_ca` (`src/util/download_int_certs.rs`);
the verification code (`security_report`, chain and permission checks) is
unchanged, and a scratch binary calling it directly on our CTL gave the same
verdict before the change (`validated_chain_index 0`).
