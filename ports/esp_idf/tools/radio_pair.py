#!/usr/bin/env python3
"""Two-C5 radio integration test, not an ETSI ATS or RF certification test.

Requires the test firmware on both boards and separately installed pyserial.
Explicit --allow-transmission enables the laboratory transmitter. Capture and
result files retain independent receiver observations.

FCS is not independently re-validated here, and that is not a gap: the
receiver's promiscuous filter (vanetza_idf::C5Radio, ports/esp_idf/src/c5_radio.cpp)
does not set WIFI_PROMIS_FILTER_MASK_FCSFAIL, so the ESP32-C5 WiFi hardware
already discards any frame that fails FCS before this callback ever sees it
(Espressif's own doc comment on that flag: "do not open it in general") --
any frame reaching this test already passed a real over-the-air FCS check.
The chip's rx_ctrl.sig_len is documented (esp_wifi_he_types.h, this chip's
802.11ax/HE RX descriptor) as "the length of the reception MPDU", not
"MPDU + FCS" as older ESP32 documentation for earlier chips states; measured
directly on this hardware, sig_len is consistently 4 bytes longer than the
actual frame content, and those 4 trailing bytes are identical
(observed: 00 00 99 00) across captures with completely different random
payloads -- proof they are not a content-derived FCS at all, just a fixed
trailer this chip's HE RX descriptor appends. Recomputing a software CRC32
over them and requiring a match, as an earlier version of this test did, can
never succeed and was not actually checking anything real; the trailing
bytes are still captured into the pcap for inspection, just not treated as
a verifiable FCS.
"""
import argparse
import json
import secrets
import struct
import time
from pathlib import Path
from serial_sut import SerialSut, records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dut', required=True)
    parser.add_argument('--receiver', required=True)
    parser.add_argument('--channel', type=int, default=180)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--allow-transmission', action='store_true', required=True)
    args = parser.parse_args()
    if args.dut.upper() == args.receiver.upper():
        parser.error('DUT and receiver must be different devices')
    if args.channel not in range(172, 185, 2):
        parser.error('Channel must be an even ITS-G5 channel from 172 through 184')
    args.out.mkdir(parents=True, exist_ok=False)
    result = {'kind': 'radio-integration', 'dut': args.dut, 'receiver': args.receiver,
              'channel': args.channel, 'status': 'error', 'captures': [], 'cleanup_errors': []}
    devices = []
    def accepted(device, command):
        status, observed = records(device.execute(command))
        if status:
            raise RuntimeError(f'Diagnostic command {command[0]} returned {status}')
        return observed
    try:
        dut = SerialSut(args.dut); devices.append(dut)
        receiver = SerialSut(args.receiver); devices.append(receiver)
        accepted(dut, b'\x00')
        payload = b'VIDF-RF-' + secrets.token_bytes(16)
        generated = accepted(dut, b'\x01\x01' + struct.pack('>HH', 2018, 0) + payload)
        packets = [data for kind, data in generated if kind == 1]
        if len(packets) != 1:
            raise RuntimeError('Expected exactly one real GeoNetworking packet')
        gn = packets[0]
        # Locally administered source address; independent receiver checks it.
        source = bytes.fromhex('020000000001')
        destination = b'\xff' * 6
        transmit = b'\x04' + source + destination + bytes([3, 2]) + gn
        channel = struct.pack('>H', args.channel)
        accepted(receiver, b'\x03' + channel + b'\x00')
        status, _ = records(receiver.execute(transmit))
        if status == 0:
            raise RuntimeError('Receive-only radio incorrectly accepted transmission')
        result['receive_only_tx_rejected'] = True
        accepted(dut, b'\x03' + channel + b'\x01')
        accepted(receiver, b'\x05') # Drain observations from before this transmission.
        accepted(dut, transmit)
        result['submission_accepted'] = True
        matched = False
        deadline = time.monotonic() + 5
        with (args.out / 'receiver.pcap').open('wb') as capture:
            # LINKTYPE_IEEE802_11 (105). Captured frames carry rx_ctrl.sig_len bytes,
            # which is 4 bytes longer than the actual frame content on this chip (see
            # the module docstring); the trailing 4 bytes are not a real FCS.
            capture.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105))
            while time.monotonic() < deadline and not matched:
                for kind, data in accepted(receiver, b'\x05'):
                    if kind != 3 or len(data) < 5:
                        raise RuntimeError('Malformed independent capture record')
                    rssi, timestamp = struct.unpack('>bI', data[:5])
                    frame = data[5:]
                    now = time.time(); sec = int(now)
                    capture.write(struct.pack('<IIII', sec, int((now-sec)*1e6), len(frame), len(frame)))
                    capture.write(frame)
                    # Reception through this promiscuous filter (no FCSFAIL bit) already
                    # means the hardware validated FCS; content match against exactly
                    # what the DUT submitted is what "independently received correctly"
                    # actually means here. The trailing 4 bytes are retained for
                    # inspection only, not treated as a verifiable FCS (see docstring).
                    exact = (len(frame) == 38 + len(gn) and frame[:2] == b'\x88\x00'
                             and frame[4:10] == destination and frame[10:16] == source
                             and frame[16:22] == destination and frame[24:26] == b'\x03\x00'
                             and frame[26:34] == bytes.fromhex('aaaa030000008947')
                             and frame[34:-4] == gn)
                    result['captures'].append({'rssi_dbm': rssi, 'device_timestamp_us': timestamp,
                                               'trailing_bytes': frame[-4:].hex() if len(frame) >= 4 else None,
                                               'exact_match': exact})
                    matched |= exact
        result['status'] = 'pass' if matched else 'fail'
        if not matched:
            result['reason'] = 'No exact independent frame observed'
    except Exception as error:
        result['reason'] = str(error)
    finally:
        for device in devices:
            try:
                accepted(device, b'\x06')
            except Exception as error:
                result['cleanup_errors'].append(str(error))
                result['status'] = 'error'
            device.close()
        (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'pass' else 1)


if __name__ == '__main__':
    main()
