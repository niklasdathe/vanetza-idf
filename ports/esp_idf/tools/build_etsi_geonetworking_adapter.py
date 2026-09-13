#!/usr/bin/env python3
"""Link the GeoNetworking SUT adapter against a separately built official ETSI framework.

Run on the same Linux/TITAN runtime as the supplied build. Never installs TTCN,
edits the ETSI source tree in place, or modifies its testcase objects or bodies.

The one exception is a disposable build overlay for a framework null-pointer bug
(see PAYLOAD_NULL_PARAMS_PATCH below): the pinned source on disk is read but never
written, only a patched copy compiled into this tool's own --out directory.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

# geonetworking_codec::decode_ (ccsrc/Protocols/GeoNetworking/geonetworking_codec.cc)
# unconditionally dereferences `_params` while decoding GnNonSecuredPacket.payload, in
# all three branches of the length-alignment logic. Every other parameter write in
# this file (in the enclosing decode(), a few lines above decode_) is correctly
# guarded with `if (_params != NULL)`; this one just wasn't. fx__dec__GeoNetworkingPdu
# (ccsrc/EncDec/LibItsGeoNetworking_Encdec.cc) always calls decode() with the default
# params (nullptr), so decoding *any* GeoNetworkingPdu through the official codec
# wrapper segfaults as soon as it reaches this field -- confirmed via a core dump
# (gdb bt full) naming this exact line, not a maybe. Never triggered by BTP (whose
# adapter never calls this decoder) or by any earlier GeoNetworking run, because no
# GN packet had ever actually been transmitted-and-observed through TITAN before
# (store-carry-forward buffering meant every prior SHB attempt just sat unsent).
PAYLOAD_NULL_PARAMS_PATCH = [
    ('          os                             = OCTETSTRING(s.lengthof(), p);\n'
     '          (*_params)[params_its::gn_payload] = static_cast<const char *>(oct2str(os));\n',
     '          os                             = OCTETSTRING(s.lengthof(), p);\n'
     '          if (_params != NULL) (*_params)[params_its::gn_payload] = static_cast<const char *>(oct2str(os));\n'),
    ('          os                             = OCTETSTRING(_dc.get_length(), p);\n'
     '          (*_params)[params_its::gn_payload] = static_cast<const char *>(oct2str(os));\n',
     '          os                             = OCTETSTRING(_dc.get_length(), p);\n'
     '          if (_params != NULL) (*_params)[params_its::gn_payload] = static_cast<const char *>(oct2str(os));\n'),
    ('        os                             = OCTETSTRING(0, nullptr);\n'
     '        (*_params)[params_its::gn_payload] = "";\n',
     '        os                             = OCTETSTRING(0, nullptr);\n'
     '        if (_params != NULL) (*_params)[params_its::gn_payload] = "";\n'),
]


def patch_geonetworking_codec(build, out, includes, compile_flags):
    source = build.parents[1] / 'ccsrc/Protocols/GeoNetworking/geonetworking_codec.cc'
    text = source.read_text()
    before_sha = hashlib.sha256(text.encode()).hexdigest()
    for old, new in PAYLOAD_NULL_PARAMS_PATCH:
        if text.count(old) != 1:
            raise SystemExit(f'geonetworking_codec.cc overlay: expected exactly one match for {old!r}')
        text = text.replace(old, new)
    patched = out / 'geonetworking_codec.patched.cc'
    patched.write_text(text)
    obj = out / 'geonetworking_codec.patched.o'
    command = compile_flags + ['-I' + str(p) for p in sorted(includes)] + ['-c', str(patched), '-o', str(obj)]
    subprocess.run(command, check=True)
    return obj, before_sha, hashlib.sha256(text.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--etsi', type=Path, required=True)
    parser.add_argument('--titan', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root, titan, out = args.etsi.resolve(), args.titan.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    build = root / 'build/AtsGeoNetworking'
    source = Path(__file__).resolve().parents[1] / 'tests/etsi_geonetworking_adapter.cpp'
    if not (build / 'ItsGeoNetworking_TestCases.o').is_file():
        raise SystemExit('Build the official AtsGeoNetworking suite separately first')
    includes = {build, titan / 'include', root / 'ccsrc/Ports/LibIts_ports/GN_ports'}
    for parent in (root / 'ccsrc', root / 'titan-test-system-framework/ccsrc'):
        includes.update(p.parent for p in parent.rglob('*.hh'))
    compile_flags = ['g++', '-std=c++17', '-g', '-O0', '-DTITAN_RUNTIME_2', '-D_NO_SOFTLINKS_',
                      '-DLINUX', '-DAtsGeoNetworking', '-DAS_USE_SSL', '-I/usr/include/libxml2', '-I/usr/include/jsoncpp']
    obj = out / 'etsi_geonetworking_adapter.o'
    subprocess.run(compile_flags + ['-I' + str(p) for p in sorted(includes)] + ['-c', str(source), '-o', str(obj)], check=True)
    codec_obj, codec_before_sha, codec_after_sha = patch_geonetworking_codec(build, out, includes, compile_flags)
    objects = sorted(p for p in build.rglob('*.o') if 'asn1' not in p.relative_to(build).parts
                     and p.name not in ('GeoNetworkingPort.o', 'UpperTesterPort_GN.o', 'AdapterControlPort_GN.o',
                                        'geonetworking_codec.o'))
    binary = out / 'AtsGeoNetworking'
    link = ['g++', '-o', str(binary), str(obj), str(codec_obj)] + [str(p) for p in objects]
    link += [str(build / 'asn1/libItsAsn.a'), str(titan / 'lib/libttcn3-rt2-parallel.a'),
             '-lstdc++fs', '-lpcap', '-lrt', '-lpthread', '-lssl', '-lcrypto', '-lxml2', '-ljsoncpp', '-lzip', '-lsctp']
    subprocess.run(link, check=True)
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    evidence = {'adapter_sha256': sha(source), 'binary_sha256': sha(binary),
                'testcase_object_sha256': sha(build / 'ItsGeoNetworking_TestCases.o'),
                'testcase_source_sha256': sha(root / 'ttcn/AtsGeoNetworking/ItsGeoNetworking_TestCases.ttcn'),
                'scope': 'Official GeoNetworking testcase objects; custom host/device SUT ports, SHB source only; no conformance verdict implied',
                'suite_overlay': [{
                    'path': 'ccsrc/Protocols/GeoNetworking/geonetworking_codec.cc',
                    'before': codec_before_sha, 'after': codec_after_sha,
                    'reason': 'Null-guard three unconditional (*_params)[...] writes while decoding '
                              'GnNonSecuredPacket.payload; fx__dec__GeoNetworkingPdu always decodes with '
                              'params=nullptr, so every decode of an observed GN packet segfaulted. Pinned '
                              'source on disk is untouched; only this tool\'s own --out build uses the patch.'
                }]}
    (out / 'build.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(binary)


if __name__ == '__main__':
    main()
