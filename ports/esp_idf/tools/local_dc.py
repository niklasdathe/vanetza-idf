#!/usr/bin/env python3
"""A distribution centre on localhost: TS 102 941 V2.2.1 Annex D, Tables D.1 and D.2.

Serves the CTL and CRL of one or more root CAs the way an ITS-S fetches them:

  GET /getctl/<HASHEDID8>              -> the latest full CTL, application/x-its-ctl
  GET /getctl/<HASHEDID8>/<sequence>   -> a delta CTL of that sequence (404 here: only full CTLs are kept)
  GET /getcrl/<HASHEDID8>              -> the CRL, application/x-its-crl

The files come from a directory holding ctl-<HASHEDID8>.oer and crl-<HASHEDID8>.oer as
vidf_issue ctl / crl write them (HASHEDID8 in upper-case hex). Nothing is verified here:
the DC is a file server; the ITS-S verifies the RCA signature (clause 6.3.6).

  local_dc.py --dir lists --port 8080

Test tool, not part of the library.
"""
import argparse
import http.server
import re
from pathlib import Path

PATTERN = re.compile(r'^/get(ctl|crl)/([0-9A-F]{16})(?:/(\d+))?/?$')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--dir', type=Path, required=True, help='directory with ctl-<HASHEDID8>.oer / crl-<HASHEDID8>.oer')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--bind', default='127.0.0.1')
    args = parser.parse_args()
    lists = args.dir.resolve()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            match = PATTERN.match(self.path)
            if not match:
                self.send_error(404, 'not a getctl/getcrl path')
                return
            kind, id8, sequence = match.groups()
            if sequence is not None:
                self.send_error(404, 'delta CTLs are not kept by this distribution centre')
                return
            path = lists / f'{kind}-{id8}.oer'
            if not path.is_file():
                self.send_error(404, f'no {kind} for {id8}')
                return
            body = path.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', f'application/x-its-{kind}')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *values):
            print('%s %s' % (self.address_string(), fmt % values), flush=True)

    server = http.server.ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f'distribution centre on http://{args.bind}:{args.port}/ serving {lists}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
