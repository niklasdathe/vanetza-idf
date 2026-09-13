#!/usr/bin/env python3
"""Link the BTP SUT adapter against a separately built official ETSI framework.

Run on the same Linux/TITAN runtime as the supplied build. Never installs TTCN,
edits the ETSI source tree, or modifies its testcase objects.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--etsi', type=Path, required=True)
    parser.add_argument('--titan', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root, titan, out = args.etsi.resolve(), args.titan.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    build = root / 'build/AtsBTP'
    source = Path(__file__).resolve().parents[1] / 'tests/etsi_btp_adapter.cpp'
    if not (build / 'ItsBtp_TestCases.o').is_file():
        raise SystemExit('Build the official AtsBTP suite separately first')
    includes = {build, titan / 'include', root / 'ccsrc/Ports/LibIts_ports/BTP_ports'}
    for parent in (root / 'ccsrc', root / 'titan-test-system-framework/ccsrc'):
        includes.update(p.parent for p in parent.rglob('*.hh'))
    obj = out / 'etsi_btp_adapter.o'
    command = ['g++', '-std=c++17', '-g', '-O0', '-DTITAN_RUNTIME_2', '-D_NO_SOFTLINKS_',
               '-DLINUX', '-DAtsBTP', '-DAS_USE_SSL', '-I/usr/include/libxml2', '-I/usr/include/jsoncpp']
    command += ['-I' + str(p) for p in sorted(includes)]
    subprocess.run(command + ['-c', str(source), '-o', str(obj)], check=True)
    objects = sorted(p for p in build.rglob('*.o') if 'asn1' not in p.relative_to(build).parts
                     and p.name not in ('BtpPort.o', 'UpperTesterPort_BTP.o'))
    binary = out / 'AtsBTP'
    link = ['g++', '-o', str(binary), str(obj)] + [str(p) for p in objects]
    link += [str(build / 'asn1/libItsAsn.a'), str(titan / 'lib/libttcn3-rt2-parallel.a'),
             '-lstdc++fs', '-lpcap', '-lrt', '-lpthread', '-lssl', '-lcrypto', '-lxml2', '-ljsoncpp', '-lzip', '-lsctp']
    subprocess.run(link, check=True)
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    evidence = {'adapter_sha256': sha(source), 'binary_sha256': sha(binary),
                'testcase_object_sha256': sha(build / 'ItsBtp_TestCases.o'),
                'testcase_source_sha256': sha(root / 'ttcn/AtsBTP/ItsBtp_TestCases.ttcn'),
                'scope': 'Official BTP testcase objects; custom host/device SUT ports; no conformance verdict implied'}
    (out / 'build.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(binary)


if __name__ == '__main__':
    main()
