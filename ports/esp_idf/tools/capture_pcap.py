#!/usr/bin/env python3
"""Record what the SUT sends as an IEEE 802.11 pcap for independent verifiers.

Drives ``vidf_sut`` (hex-line protocol, see tests/hil_stdio.cpp) with a credential
chain from a pool directory, or a device running the test application over its USB
serial diagnostic channel (``--port`` with a credential bundle from
credential_bundle.py), triggers the CAM and DENM carriers and writes every AL-DATA.request as a
data frame (linktype 105, no radiotap header) as sent outside the context of a
BSS (EN 302 663 V1.3.1 clause 4.3.4, dot11OCBActivated; Annex C: the BSSID is the
wildcard in every frame), LLC/SNAP with the GeoNetworking EtherType 0x8947
(clause 4.3.3).
A verifier such as c-its-pcap (https://github.com/TheEnbyperor/c-its) can then
check the signatures and certificate chains against the root it is given.

This is a test tool, not part of the library; it makes no verdict of its own.
"""
import argparse
import struct
import subprocess
import sys
import time
from pathlib import Path

ITS_EPOCH_UNIX = 1072915200  # 2004-01-01T00:00:00Z
LEAP_SECONDS = 5             # TAI - UTC since the ITS epoch (TS 102 894-2 TimestampIts)
GEONETWORKING_ETHERTYPE = b'\x89\x47'
WILDCARD_BSSID = bytes([0xff] * 6)


class HostSut:
    def __init__(self, executable, pool=None, root=None, authorities=(), ticket=None, bundle=None):
        if bundle:
            command = [executable, '--security-bundle', bundle]
        else:
            command = [executable, '--security-pool', pool, '--root', root, '--at', ticket]
            for authority in authorities:
                command += ['--aa', authority]
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def execute(self, payload):
        self.process.stdin.write(payload.hex() + '\n')
        self.process.stdin.flush()
        reply = bytes.fromhex(self.process.stdout.readline().strip())
        result, count = reply[0], reply[1]
        records, at = [], 2
        for _ in range(count):
            kind, size = reply[at], struct.unpack('>H', reply[at + 1:at + 3])[0]
            records.append((kind, reply[at + 3:at + 3 + size]))
            at += 3 + size
        return result, records

    def close(self):
        self.process.stdin.close()
        self.process.wait()


class DeviceSut:
    """the same command protocol over the USB serial diagnostic channel (serial_sut.py)"""
    def __init__(self, port, bundle):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import serial_sut
        self.serial = serial_sut.SerialSut(port)
        serial_sut.provision(self.serial, bundle)

    def execute(self, payload):
        reply = self.serial.execute(payload)
        result, count = reply[0], reply[1]
        records, at = [], 2
        for _ in range(count):
            kind, size = reply[at], struct.unpack('>H', reply[at + 1:at + 3])[0]
            records.append((kind, reply[at + 3:at + 3 + size]))
            at += 3 + size
        return result, records

    def close(self):
        self.serial.close()


def its_microseconds(unix_seconds):
    return int((unix_seconds - ITS_EPOCH_UNIX + LEAP_SECONDS) * 1_000_000)


def write_pcap(path, frames, source):
    with open(path, 'wb') as out:
        out.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105))
        for sequence, (timestamp, pdu) in enumerate(frames):
            header = (struct.pack('<HH', 0x0008, 0) + WILDCARD_BSSID + source + WILDCARD_BSSID +
                      struct.pack('<H', (sequence & 0x0fff) << 4))
            frame = header + b'\xaa\xaa\x03\x00\x00\x00' + GEONETWORKING_ETHERTYPE + pdu
            out.write(struct.pack('<IIII', int(timestamp), int((timestamp % 1) * 1_000_000), len(frame), len(frame)))
            out.write(frame)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--sut', help='vidf_sut executable (host station)')
    parser.add_argument('--pool', help='directory with <name>.oer / <name>.vkey (with --sut)')
    parser.add_argument('--root', help='root name in the pool (with --sut)')
    parser.add_argument('--aa', action='append', default=[], help='trusted authority (repeatable, with --sut)')
    parser.add_argument('--at', help='authorization ticket of the SUT (with --sut)')
    parser.add_argument('--port', help='serial port of a device running the test application (device station)')
    parser.add_argument('--bundle', help='credential bundle (credential_bundle.py build): with --port for the device, with --sut instead of --pool/--root/--at')
    parser.add_argument('--out', required=True, help='pcap file to write')
    parser.add_argument('--cams', type=int, default=3, help='CAM carriers to trigger (default 3)')
    parser.add_argument('--interval', type=float, default=0.6, help='ITS clock advance between carriers in seconds')
    args = parser.parse_args()

    if args.port:
        if not args.bundle:
            raise SystemExit('--port needs --bundle')
        sut = DeviceSut(args.port, args.bundle)
    elif args.sut and args.bundle:
        sut = HostSut(args.sut, bundle=args.bundle)
    elif args.sut and args.pool and args.root and args.at:
        sut = HostSut(args.sut, args.pool, args.root, args.aa or ['CERT_IUT_A_AA'], args.at)
    else:
        raise SystemExit('either --sut with --bundle or --pool/--root/--at, or --port with --bundle')
    result, _ = sut.execute(bytes([0]))
    if result != 0:
        raise SystemExit('SUT reset failed (result %d): credentials not loaded' % result)
    frames = []
    now = time.time()

    def tick(at):
        result, records = sut.execute(bytes([5]) + its_microseconds(at).to_bytes(8, 'big'))
        frames.extend((at, data) for kind, data in records if kind == 1)
        return result

    def carrier(at, kind):
        # command 8 defers the carrier to the next clock advance (command 5), the path the
        # ETSI adapter uses; the frame surfaces in that advance's records
        result, records = sut.execute(bytes([8, kind]))
        result, records = sut.execute(bytes([5]) + its_microseconds(at + 0.01).to_bytes(8, 'big'))
        frames.extend((at, data) for k, data in records if k == 1)
        print('carrier %d at +%.1fs -> result %d, %d frame(s)' % (kind, at - now, result, sum(1 for k, _ in records if k == 1)))

    tick(now)
    for n in range(args.cams):
        at = now + n * args.interval
        tick(at)
        carrier(at, 0)
    at = now + args.cams * args.interval
    tick(at)
    carrier(at, 1)
    tick(at + 0.1)
    tick(at + 1.5)
    sut.close()
    write_pcap(args.out, frames, bytes([0x02, 0, 0, 0, 0, 1]))
    print('%d frame(s) written to %s' % (len(frames), args.out))


if __name__ == '__main__':
    main()
