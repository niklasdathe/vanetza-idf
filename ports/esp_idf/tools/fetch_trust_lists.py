#!/usr/bin/env python3
"""Fetch a root CA's CTL and CRL from a distribution centre (TS 102 941 V2.2.1 Annex D).

  fetch_trust_lists.py --dc http://127.0.0.1:8080/ --root ROOT.oer --out DIR

GET <dc>/getctl/<HASHEDID8> and <dc>/getcrl/<HASHEDID8> with the root's HashedId8
(upper-case hex of the last eight octets of SHA-256 over the certificate), saved as
DIR/ctl-<HASHEDID8>.oer and DIR/crl-<HASHEDID8>.oer. Nothing is verified here: read
them back with `vidf_issue inspect FILE --root ROOT.oer`, which applies the checks of
clause 6.3.6, or hand them to the station (pki::parse_rca_ctl / parse_crl / apply).
The transport is the application's; this is the test tool's version of it.
"""
import argparse
import hashlib
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--dc', required=True, help='DC access point, e.g. http://127.0.0.1:8080/')
    parser.add_argument('--root', type=Path, required=True, help='root CA certificate (COER)')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    id8 = hashlib.sha256(args.root.read_bytes()).digest()[-8:].hex().upper()
    base = args.dc if args.dc.endswith('/') else args.dc + '/'
    args.out.mkdir(parents=True, exist_ok=True)
    for kind in ('ctl', 'crl'):
        url = f'{base}get{kind}/{id8}'
        with urllib.request.urlopen(url, timeout=10) as response:
            body = response.read()
            content_type = response.headers.get('Content-Type', '')
        if content_type != f'application/x-its-{kind}':
            print(f'{url}: unexpected Content-Type {content_type!r} (Annex D: application/x-its-{kind})')
        target = args.out / f'{kind}-{id8}.oer'
        target.write_bytes(body)
        print(f'{url} -> {target} ({len(body)} octets)')


if __name__ == '__main__':
    main()
