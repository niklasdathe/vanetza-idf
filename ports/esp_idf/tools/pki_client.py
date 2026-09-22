#!/usr/bin/env python3
"""The ITS-S side of TS 102 941 V2.2.1 clause 6.2.3, over a real HTTP round trip.

`vanetza_idf::pki` builds and parses the enrolment/authorization messages; per its
own doc comment, transport to the EA/AA is "supplied by the application" (clause 6.1
reference points S3/S4, HTTP in practice). This is that application: it shells out
to `vidf_issue enrol-request`/`enrol-response` (or `authorize-*`) for the message
building/parsing and does only the POST in between, the way fetch_trust_lists.py
does only the GETs for the distribution centre.

  pki_client.py --issue-tool build/vidf_issue --pki http://127.0.0.1:8090/ enrol \
                --ea EA.oer --canonical-key canonical.pem --its-id my-station \
                --out EC.oer --out-key EC.vkey
  pki_client.py --issue-tool build/vidf_issue --pki http://127.0.0.1:8090/ authorize \
                --ea EA.oer --aa AA.oer --ec EC.oer --ec-key EC.vkey \
                --out AT.oer --out-key AT.vkey

Test tool, not part of the library.
"""
import argparse
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


def run(issue_tool, *tool_args):
    result = subprocess.run([str(issue_tool), *tool_args], capture_output=True, text=True)
    if result.stdout:
        print(result.stdout.strip(), flush=True)
    if result.returncode != 0:
        sys.exit(result.stderr.strip() or f'{tool_args[0]} failed')


def post(url, body):
    request = urllib.request.Request(url, data=body, method='POST', headers={'Content-Type': 'application/octet-stream'})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        sys.exit(f'{url}: HTTP {error.code} {error.reason}: {error.read().decode(errors="replace")}')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--issue-tool', type=Path, required=True)
    parser.add_argument('--pki', required=True, help='EA/AA access point, e.g. http://127.0.0.1:8090/')
    sub = parser.add_subparsers(dest='command', required=True)

    enrol = sub.add_parser('enrol')
    enrol.add_argument('--ea', required=True)
    enrol.add_argument('--canonical-key', required=True)
    enrol.add_argument('--its-id', required=True)
    enrol.add_argument('--permission', action='append', default=[])
    enrol.add_argument('--out', required=True)
    enrol.add_argument('--out-key', required=True)

    authorize = sub.add_parser('authorize')
    authorize.add_argument('--ea', required=True)
    authorize.add_argument('--aa', required=True)
    authorize.add_argument('--ec', required=True)
    authorize.add_argument('--ec-key', required=True)
    authorize.add_argument('--permission', action='append', default=[])
    authorize.add_argument('--hours', default='24')
    authorize.add_argument('--out', required=True)
    authorize.add_argument('--out-key', required=True)

    args = parser.parse_args()
    base = args.pki if args.pki.endswith('/') else args.pki + '/'

    with tempfile.TemporaryDirectory() as tmp:
        request_path, context_path, response_path = (Path(tmp) / name for name in ('request.bin', 'context.bin', 'response.bin'))
        if args.command == 'enrol':
            build_args = ['enrol-request', '--ea', args.ea, '--canonical-key', args.canonical_key, '--its-id', args.its_id,
                          '--out', str(request_path), '--context', str(context_path), '--out-key', args.out_key]
            for permission in args.permission:
                build_args += ['--permission', permission]
            run(args.issue_tool, *build_args)
            response = post(base + 'ea/enrolment', request_path.read_bytes())
            response_path.write_bytes(response)
            run(args.issue_tool, 'enrol-response', '--ea', args.ea, '--context', str(context_path),
                '--response', str(response_path), '--out', args.out)
        else:
            build_args = ['authorize-request', '--ea', args.ea, '--aa', args.aa, '--ec', args.ec, '--ec-key', args.ec_key,
                          '--hours', args.hours, '--out', str(request_path), '--context', str(context_path),
                          '--out-key', args.out_key]
            for permission in args.permission:
                build_args += ['--permission', permission]
            run(args.issue_tool, *build_args)
            response = post(base + 'aa/authorization', request_path.read_bytes())
            response_path.write_bytes(response)
            run(args.issue_tool, 'authorize-response', '--aa', args.aa, '--context', str(context_path),
                '--response', str(response_path), '--out', args.out)


if __name__ == '__main__':
    main()
