#!/usr/bin/env python3
"""Hex-line SUT process for external TTCN adapters; USB carries VID1 frames.

Requires separately installed pyserial. This is a test application transport,
not a TTCN runtime, ETSI UT codec or source of test verdicts.
"""
import argparse
import struct
import sys
import time
import zlib


class SerialSut:
    def __init__(self, port, timeout=8):
        import serial
        self.port = serial.Serial(port=None, baudrate=115200, timeout=0.1, write_timeout=timeout)
        self.port.dtr = False
        self.port.rts = False
        self.port.port = port
        self.port.open()
        self.timeout = timeout
        self.sequence = 0
        self.buffer = bytearray()

    def close(self):
        self.port.close()

    def execute(self, payload):
        if not 0 < len(payload) <= 4096:
            raise ValueError('Diagnostic payload must contain 1..4096 octets')
        self.sequence = (self.sequence + 1) & 0xffffffff
        frame = b'VID1' + struct.pack('>BIH', 3, self.sequence, len(payload)) + payload
        frame += struct.pack('>I', zlib.crc32(frame))
        if self.port.write(frame) != len(frame):
            raise IOError('Incomplete SUT write')
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            self.buffer.extend(self.port.read(4096))
            while len(self.buffer) >= 4:
                if self.buffer[:4] != b'VID1':
                    del self.buffer[0]
                    continue
                if len(self.buffer) < 11:
                    break
                channel, sequence, size = struct.unpack('>BIH', self.buffer[4:11])
                if channel not in (1, 2, 3) or not 0 < size <= 4096:
                    del self.buffer[0]
                    continue
                if len(self.buffer) < size + 15:
                    break
                raw = bytes(self.buffer[:size + 15])
                if zlib.crc32(raw[:-4]) != struct.unpack('>I', raw[-4:])[0]:
                    del self.buffer[0]
                    continue
                del self.buffer[:size + 15]
                if channel == 3 and sequence == self.sequence:
                    return raw[11:-4]
        raise TimeoutError('No matching device response; no verdict inferred')


def records(response):
    if len(response) < 2:
        raise ValueError('Truncated SUT response')
    count = response[1]
    offset = 2
    decoded = []
    for _ in range(count):
        if offset + 3 > len(response):
            raise ValueError('Truncated record header')
        kind, size = struct.unpack_from('>BH', response, offset)
        offset += 3
        if offset + size > len(response):
            raise ValueError('Truncated record data')
        decoded.append((kind, response[offset:offset + size]))
        offset += size
    if offset != len(response):
        raise ValueError('Trailing response data')
    return response[0], decoded


def provision(sut, bundle_path):
    """Diagnostic command 9: a credential bundle (credentials.hpp) for the next reset."""
    bundle = open(bundle_path, 'rb').read()
    if len(bundle) > 4095:
        raise ValueError('The bundle exceeds one diagnostic frame (4095 octets)')
    result, _ = records(sut.execute(b'	' + bundle))
    if result != 0:
        raise RuntimeError('The device refused the credential bundle (result %d)' % result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    parser.add_argument('--bundle', help='credential bundle sent as diagnostic command 9 before relaying stdin')
    args = parser.parse_args()
    sut = SerialSut(args.port)
    try:
        if args.bundle:
            provision(sut, args.bundle)
        for line in sys.stdin:
            if len(line) > 8193:
                raise ValueError('Oversized input line')
            response = sut.execute(bytes.fromhex(line.strip()))
            records(response)
            print(response.hex(), flush=True)
    finally:
        sut.close()


if __name__ == '__main__':
    main()
