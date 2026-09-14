#!/usr/bin/env python3
"""Build or inspect a credential bundle (vanetza_idf/credentials.hpp, format "VCR1").

A bundle carries what a station keeps: root CA certificates, subordinate CA
certificates, and authorization tickets with their private keys, as records
[type 1 octet][length 2 octets big-endian][payload]; types 1 root, 2 authority,
3 ticket certificate, 4 ticket key ([curve 1 octet: 1 NIST P-256, 2 brainpoolP256r1,
3 brainpoolP384r1][scalar]) directly after its certificate.

  credential_bundle.py build --pool DIR --root NAME [--aa NAME]... --at NAME [--at NAME]... --out FILE
      NAME.oer (and NAME.vkey for tickets) from the pool directory, e.g. what
      vidf_issue or vidf_test_pool wrote.
  credential_bundle.py show FILE
      list the records (lengths and HashedId8 of each certificate).

Private keys travel in the clear inside the bundle: keep the file like the keys.
This is a test tool, not part of the library.
"""
import argparse
import hashlib
import struct
from pathlib import Path

MAGIC = b'VCR1'
ROOT, AUTHORITY, TICKET, TICKET_KEY = 1, 2, 3, 4
CURVE_BY_LENGTH = {32: 1, 48: 3}  # a 32-octet scalar is taken as NIST P-256 (the pool's default)


def record(kind, payload):
    if not 0 < len(payload) < 65536:
        raise ValueError('record payload must be 1..65535 octets')
    return struct.pack('>BH', kind, len(payload)) + payload


def build(pool, root, authorities, tickets):
    out = bytearray(MAGIC)
    out += record(ROOT, (pool / f'{root}.oer').read_bytes())
    for name in authorities:
        out += record(AUTHORITY, (pool / f'{name}.oer').read_bytes())
    for name in tickets:
        out += record(TICKET, (pool / f'{name}.oer').read_bytes())
        scalar = (pool / f'{name}.vkey').read_bytes()
        if len(scalar) not in CURVE_BY_LENGTH:
            raise ValueError(f'{name}.vkey: {len(scalar)} octets is no supported scalar length')
        out += record(TICKET_KEY, bytes([CURVE_BY_LENGTH[len(scalar)]]) + scalar)
    return bytes(out)


def parse(bundle):
    if bundle[:4] != MAGIC:
        raise ValueError('not a VCR1 bundle')
    at, records = 4, []
    while at < len(bundle):
        kind, length = struct.unpack_from('>BH', bundle, at)
        at += 3
        payload = bundle[at:at + length]
        if len(payload) != length or length == 0:
            raise ValueError('truncated or empty record')
        at += length
        records.append((kind, payload))
    return records


def hashed_id8(coer):
    return hashlib.sha256(coer).digest()[-8:].hex().upper()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    b = sub.add_parser('build')
    b.add_argument('--pool', type=Path, required=True)
    b.add_argument('--root', required=True)
    b.add_argument('--aa', action='append', default=[])
    b.add_argument('--at', action='append', default=[], required=True)
    b.add_argument('--out', type=Path, required=True)
    s = sub.add_parser('show')
    s.add_argument('file', type=Path)
    args = parser.parse_args()
    if args.command == 'build':
        bundle = build(args.pool, args.root, args.aa, args.at)
        args.out.write_bytes(bundle)
        print(f'{len(bundle)} octets: 1 root, {len(args.aa)} authorit{"y" if len(args.aa) == 1 else "ies"}, {len(args.at)} ticket(s) -> {args.out}')
    else:
        names = {ROOT: 'root', AUTHORITY: 'authority', TICKET: 'ticket', TICKET_KEY: 'ticket key'}
        for kind, payload in parse(args.file.read_bytes()):
            if kind == TICKET_KEY:
                print(f'  {names[kind]:11} curve {payload[0]}, {len(payload) - 1} octets (not shown)')
            else:
                print(f'  {names.get(kind, kind):11} {len(payload):4} octets  HashedId8 {hashed_id8(payload)}')


if __name__ == '__main__':
    main()
