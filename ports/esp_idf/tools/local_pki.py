#!/usr/bin/env python3
"""An EA and AA on localhost: TS 102 941 V2.2.1 clause 6.2.3 enrolment/authorization.

Serves the two HTTP endpoints an ITS-S POSTs its requests to:

  POST /ea/enrolment      body = EnrolmentRequest (EtsiTs103097Data-Encrypted)
                           ->    EnrolmentResponse (EtsiTs103097Data-Encrypted), 200
  POST /aa/authorization   body = AuthorizationRequest (EtsiTs103097Data-Encrypted)
                           ->    AuthorizationResponse (EtsiTs103097Data-Encrypted), 200

This tool carries bytes only: every decrypt, signature check, certificate issuance
and re-encryption is done by `vidf_issue ea-respond` / `aa-respond` (VIDF_PKI=ON),
run once per request as a subprocess -- exactly the division of labour local_dc.py
has for the distribution centre, just for clause 6.2.3 instead of clause 6.3. A
request `vidf_issue` cannot decrypt/verify/decode gets HTTP 400: a real ITS-S never
sends one, so this is tooling clarity, not part of the TS 102 941 message exchange.

  local_pki.py --issue-tool build/vidf_issue \
               --ea EA.oer --ea-key EA.vkey --ea-enc-key EA.ekey --canonical-key canonical.pem \
               --aa AA.oer --aa-key AA.vkey --aa-enc-key AA.ekey \
               --dir issued --port 8090

--canonical-key is the initial-enrolment case only (clause 6.2.3.2.1): the EA is
handed the same canonical private key file the station used, standing in for the
manufacturer's out-of-band registry a lab has no other side of. Re-enrolment
(--current-ec) is not wired up here; use `vidf_issue ea-respond --current-ec`
directly for that.

Test tool, not part of the library.
"""
import argparse
import http.server
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--issue-tool', type=Path, required=True, help='path to the vidf_issue binary (VIDF_PKI=ON)')
    parser.add_argument('--ea', type=Path, required=True)
    parser.add_argument('--ea-key', type=Path, required=True)
    parser.add_argument('--ea-enc-key', type=Path, required=True)
    parser.add_argument('--canonical-key', type=Path, required=True, help='initial enrolment only, see above')
    parser.add_argument('--aa', type=Path, required=True)
    parser.add_argument('--aa-key', type=Path, required=True)
    parser.add_argument('--aa-enc-key', type=Path, required=True)
    parser.add_argument('--dir', type=Path, required=True, help='EC store ea-respond writes to and aa-respond reads from')
    parser.add_argument('--port', type=int, default=8090)
    parser.add_argument('--bind', default='127.0.0.1')
    args = parser.parse_args()
    args.dir.mkdir(parents=True, exist_ok=True)

    def respond(tool_args, request_body):
        with tempfile.TemporaryDirectory() as tmp:
            request_path = Path(tmp) / 'request.bin'
            response_path = Path(tmp) / 'response.bin'
            request_path.write_bytes(request_body)
            result = subprocess.run(
                [str(args.issue_tool), *tool_args, '--request', str(request_path), '--out', str(response_path)],
                capture_output=True, text=True)
            if result.returncode != 0:
                return None, result.stdout + result.stderr
            return response_path.read_bytes(), result.stdout + result.stderr

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            if self.path == '/ea/enrolment':
                tool_args = ['ea-respond', '--ea', str(args.ea), '--ea-key', str(args.ea_key),
                             '--ea-enc-key', str(args.ea_enc_key), '--canonical-key', str(args.canonical_key),
                             '--dir', str(args.dir)]
            elif self.path == '/aa/authorization':
                tool_args = ['aa-respond', '--aa', str(args.aa), '--aa-key', str(args.aa_key),
                             '--aa-enc-key', str(args.aa_enc_key), '--ea', str(args.ea), '--ea-key', str(args.ea_key),
                             '--ea-enc-key', str(args.ea_enc_key), '--ec-dir', str(args.dir)]
            else:
                self.send_error(404, 'only /ea/enrolment and /aa/authorization are served')
                return
            response, log = respond(tool_args, body)
            print(log.strip(), flush=True)
            if response is None:
                self.send_error(400, 'request did not decrypt/verify/decode')
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, fmt, *values):
            print('%s %s' % (self.address_string(), fmt % values), flush=True)

    server = http.server.ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f'EA/AA on http://{args.bind}:{args.port}/ (ea/enrolment, aa/authorization), EC store {args.dir.resolve()}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    sys.exit(main())
