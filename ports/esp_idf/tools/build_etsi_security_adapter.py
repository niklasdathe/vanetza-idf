#!/usr/bin/env python3
"""Link this library's AtsSecurity SUT adapter with the user's compiled ETSI suite.

Mirrors build_etsi_geonetworking_adapter.py: the official testcase objects of a
separately built AtsSecurity are reused unchanged; the framework's own
GeoNetworking/CAM/DENM port objects are replaced by ports/esp_idf/tests/
etsi_security_adapter.cpp, and the same disposable geonetworking_codec.cc
overlay (null params guard) is applied to this build's output only. Retain the
printed build.json next to the campaign result.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_etsi_geonetworking_adapter import patch_geonetworking_codec  # noqa: E402

REPLACED_OBJECTS = ('GeoNetworkingPort.o', 'UpperTesterPort_GN.o', 'AdapterControlPort_GN.o',
                    'UpperTesterPort_CAM.o', 'UpperTesterPort_DENM.o', 'geonetworking_codec.o')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--etsi', type=Path, required=True)
    parser.add_argument('--titan', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root, titan, out = args.etsi.resolve(), args.titan.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    build = root / 'build/AtsSecurity'
    source = Path(__file__).resolve().parents[1] / 'tests/etsi_security_adapter.cpp'
    if not (build / 'ItsSecurity_TestCases.o').is_file():
        raise SystemExit('Build the official AtsSecurity suite separately first')
    ports = root / 'ccsrc/Ports/LibIts_ports'
    includes = {build, titan / 'include', ports / 'GN_ports', ports / 'CAM_ports', ports / 'DENM_ports',
                Path(__file__).resolve().parents[1] / 'include'}  # vanetza_idf/its_time.hpp (header-only)
    for parent in (root / 'ccsrc', root / 'titan-test-system-framework/ccsrc'):
        includes.update(p.parent for p in parent.rglob('*.hh'))
    compile_flags = ['g++', '-std=c++17', '-g', '-O0', '-DTITAN_RUNTIME_2', '-D_NO_SOFTLINKS_',
                      '-DLINUX', '-DAtsSecurity', '-DAS_USE_SSL', '-I/usr/include/libxml2', '-I/usr/include/jsoncpp']
    obj = out / 'etsi_security_adapter.o'
    subprocess.run(compile_flags + ['-I' + str(p) for p in sorted(includes)] + ['-c', str(source), '-o', str(obj)], check=True)
    codec_obj, codec_before_sha, codec_after_sha = patch_geonetworking_codec(build, out, includes, compile_flags)
    objects = sorted(p for p in build.rglob('*.o') if 'asn1' not in p.relative_to(build).parts
                     and p.name not in REPLACED_OBJECTS)
    binary = out / 'AtsSecurity'
    link = ['g++', '-o', str(binary), str(obj), str(codec_obj)] + [str(p) for p in objects]
    link += [str(build / 'asn1/libItsAsn.a'), str(titan / 'lib/libttcn3-rt2-parallel.a'),
             '-lstdc++fs', '-lpcap', '-lrt', '-lpthread', '-lssl', '-lcrypto', '-lxml2', '-ljsoncpp', '-lzip', '-lsctp']
    subprocess.run(link, check=True)
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    evidence = {'adapter_sha256': sha(source), 'binary_sha256': sha(binary),
                'testcase_object_sha256': sha(build / 'ItsSecurity_TestCases.o'),
                'testcase_source_sha256': sha(root / 'ttcn/AtsSecurity/ItsSecurity_TestCases.ttcn'),
                'scope': 'Official Security testcase objects; custom host SUT ports for the sending side '
                         '(GN-MGMT beacons, CAM/DENM carriers); receiving cases not wired; no conformance verdict implied',
                'suite_overlay': [{
                    'path': 'ccsrc/Protocols/GeoNetworking/geonetworking_codec.cc',
                    'before': codec_before_sha, 'after': codec_after_sha,
                    'reason': 'Same null-params guard as the GeoNetworking adapter build; pinned source untouched.'
                }]}
    (out / 'build.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(binary)


if __name__ == '__main__':
    main()
