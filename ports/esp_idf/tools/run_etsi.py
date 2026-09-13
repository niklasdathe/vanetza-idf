#!/usr/bin/env python3
"""Execute an externally installed TITAN suite and retain real verdicts.

The supplied configuration owns PICS/PIXIT, test ports and testcase selection.
This runner does not install TTCN, rewrite testcases or treat process exit as PASS.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('titan', 'binary', 'config', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--sut', type=Path)
    parser.add_argument('--sut-script')
    parser.add_argument('--port')
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--expected-cases', type=Path, required=True,
                        help='JSON array of the exact testcase names expected in this campaign')
    args = parser.parse_args()
    expected = json.loads(args.expected_cases.read_text())
    if (not isinstance(expected, list) or not expected or
            any(not isinstance(case, str) or not case for case in expected) or
            len(expected) != len(set(expected))):
        parser.error('--expected-cases must contain a nonempty array of unique testcase names')
    titan, binary, config, out = [p.resolve() for p in (args.titan, args.binary, args.config, args.out)]
    out.mkdir(parents=True, exist_ok=False)
    shutil.copy2(config, out / 'test.cfg')
    shutil.copy2(args.expected_cases, out / 'expected-cases.json')
    env = dict(os.environ)
    env.update(TTCN3_DIR=str(titan), LD_LIBRARY_PATH=str(titan / 'lib'),
               PATH=str(titan / 'bin') + ':' + env.get('PATH', ''))
    if args.sut:
        env['VIDF_SUT_EXECUTABLE'] = str(args.sut.resolve())
    if args.sut_script:
        env['VIDF_SUT_SCRIPT'] = args.sut_script
    if args.port:
        env['VIDF_SUT_PORT'] = args.port
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    metadata = {'started_utc': datetime.now(timezone.utc).isoformat(),
                'binary_sha256': sha(binary), 'config_sha256': sha(config),
                'sut_sha256': sha(args.sut) if args.sut else None,
                'expected_cases_sha256': sha(args.expected_cases),
                'verdicts': [], 'status': 'running'}
    with (out / 'console.txt').open('w') as log:
        process = subprocess.Popen([str(titan / 'bin/ttcn3_start'), str(binary), 'test.cfg'],
                                   cwd=out, env=env, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            metadata['exit_code'] = process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=15)
            metadata['exit_code'] = None
            metadata['status'] = 'runner-timeout'
    logs = sorted(out.glob('*mtc*.log'))
    text = '\n'.join(p.read_text(errors='replace') for p in logs) if logs else (out / 'console.txt').read_text(errors='replace')
    metadata['verdicts'] = [{'testcase': case, 'verdict': verdict.lower()} for case, verdict in
                           re.findall(r'Test case (\S+) finished\. Verdict: (\w+)', text)]
    observed = [v['testcase'] for v in metadata['verdicts']]
    metadata['missing_cases'] = sorted(set(expected) - set(observed))
    metadata['unexpected_cases'] = sorted(set(observed) - set(expected))
    metadata['duplicate_cases'] = sorted({case for case in observed if observed.count(case) > 1})
    metadata['campaign_complete'] = not any(metadata[key] for key in
        ('missing_cases', 'unexpected_cases', 'duplicate_cases'))
    if metadata['status'] == 'running':
        metadata['status'] = 'completed' if metadata['exit_code'] == 0 else 'runner-error'
    metadata['finished_utc'] = datetime.now(timezone.utc).isoformat()
    (out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps(metadata, indent=2))
    passed = metadata['status'] == 'completed' and metadata['campaign_complete'] and all(
        v['verdict'] == 'pass' for v in metadata['verdicts'])
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
