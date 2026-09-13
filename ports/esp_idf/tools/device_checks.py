#!/usr/bin/env python3
"""Reset a flashed C5 test application and retain its component-test output.

Requires pyserial and esptool from the user's ESP-IDF environment.
This produces component-test evidence, never an ETSI ATS verdict.
"""
import argparse
import json
import re
import time
from pathlib import Path
from esptool.reset import HardReset
from serial_sut import SerialSut


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=30.0,
                        help='seconds to wait for VIDF_TEST_RESULT (security builds need about 90)')
    parser.add_argument('--no-reset', action='store_true',
                        help='only listen: use right after "idf.py flash", whose own reset boots the '
                             'application (a DTR/RTS reset can leave the ESP32-C5 ROM waiting for UART0, '
                             'see docs/idf/validation.md)')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    result = {'kind': 'component-tests', 'port': args.port, 'status': 'error'}
    output = bytearray()
    device = None
    try:
        device = SerialSut(args.port)
        device.port.reset_input_buffer()
        if not args.no_reset:
            HardReset(device.port, uses_usb=True)()
        result['reset'] = 'none' if args.no_reset else 'usb-hard-reset'
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            output.extend(device.port.read(4096))
            if b'VIDF_TEST_RESULT=' in output and re.search(rb'VIDF_TEST_RESULT=\d+\r?\n', output):
                break
        text = output.decode(errors='replace')
        match = re.search(r'PASS: (\d+) checks', text)
        result['checks'] = int(match.group(1)) if match else None
        result['status'] = 'pass' if match and 'VIDF_TEST_RESULT=0' in text else 'fail'
    except Exception as error:
        result['reason'] = str(error)
    finally:
        if device:
            device.close()
        (args.out / 'console.txt').write_bytes(output)
        (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    print(output.decode(errors='replace'))
    raise SystemExit(0 if result['status'] == 'pass' else 1)


if __name__ == '__main__':
    main()
