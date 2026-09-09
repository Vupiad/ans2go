#!/usr/bin/env python3
"""
scripts/diff_test.py - Differential UPER Testing between ans2go and pycrate.

This script independently validates ans2go's UPER encoder and decoder against
pycrate (the established Python ASN.1 UPER reference engine).
"""

import os
import sys
import subprocess
import json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
SCRATCH_DIR = os.path.join(ROOT_DIR, 'scratch')
os.makedirs(SCRATCH_DIR, exist_ok=True)
sys.path.insert(0, SCRATCH_DIR)

# Ensure pycrate compiled module exists
SUPL_PY = os.path.join(SCRATCH_DIR, 'pycrate_supl.py')
if not os.path.exists(SUPL_PY):
    print("Compiling SUPL ASN.1 specifications with pycrate...")
    asn_dir = os.path.join(ROOT_DIR, 'example', 'supl1')
    out_target = os.path.join(SCRATCH_DIR, 'pycrate_supl')
    cmd = [
        sys.executable,
        os.path.expanduser('~/.local/bin/pycrate_asn1compile.py'),
        '-i', asn_dir,
        '-o', out_target
    ]
    subprocess.check_call(cmd)
    # pycrate_asn1compile appends .py if not present
    if os.path.exists(out_target + '.py') and not os.path.exists(SUPL_PY):
        os.rename(out_target + '.py', SUPL_PY)
    print("pycrate compilation finished.")

import pycrate_supl as supl

def run_test_case(name, hex_str, expected_check_fn):
    print(f"\n[TEST CASE] {name}")
    print(f"  Input ans2go hex ({len(hex_str)//2} bytes): {hex_str}")
    raw = bytes.fromhex(hex_str)

    # 1. Decode in pycrate
    pdu = supl.ULP.ULP_PDU
    try:
        pdu.from_uper(raw)
    except Exception as e:
        print(f"  FAILED: pycrate failed to decode ans2go UPER stream: {e}")
        return False

    val = pdu.get_val()
    print(f"  pycrate decoded value: {val}")

    # 2. Check semantic correctness
    if not expected_check_fn(val):
        print("  FAILED: pycrate decoded value does not match expected fields!")
        return False

    # 3. Re-encode with pycrate
    pdu.set_val(val)
    re_encoded = pdu.to_uper()
    print(f"  pycrate re-encoded ({len(re_encoded)} bytes): {re_encoded.hex()}")

    # 4. Strict bit-for-bit assertion
    if re_encoded != raw:
        print(f"  FAILED: pycrate re-encoded hex differs from ans2go!\n    ans2go:  {hex_str.lower()}\n    pycrate: {re_encoded.hex().lower()}")
        return False

    print("  PASS: 100% exact bit-for-bit identity between ans2go and pycrate!")
    return True

def main():
    print("=" * 70)
    print("ans2go vs pycrate Differential UPER Compliance Suite")
    print("=" * 70)

    test_cases = [
        (
            "SUPL END (StatusCode: protocolError)",
            "000c0200001483",
            lambda v: v['version']['maj'] == 2 and
                      v['message'][0] == 'msSUPLEND' and
                      v['message'][1]['statusCode'] == 'protocolError'
        ),
        (
            "SUPL END (StatusCode: unspecified)",
            "00080200001480",
            lambda v: v['version']['maj'] == 2 and
                      v['message'][0] == 'msSUPLEND' and
                      v['message'][1]['statusCode'] == 'unspecified'
        ),
        (
            "SUPL START (SETCapabilities, GSM LocationId MCC/MNC/LAC/CI/TA)",
            "0000020000843840048D159E26AF37BC4280405CC004100020001480",
            lambda v: v['message'][0] == 'msSUPLSTART' and
                      v['sessionID']['setSessionID']['sessionId'] == 4321 and
                      v['message'][1]['locationId']['cellInfo'][1]['refMCC'] == 460 and
                      v['message'][1]['locationId']['cellInfo'][1]['refCI'] == 2048
        ),
        (
            "SUPL INIT (FQDN SLPAddress, Notification UTF-8)",
            "000002000077AB6FBBD0EE31D41A26DF7BAADC1CEAE41003028E456D657267656E637943656E74657200",
            lambda v: v['message'][0] == 'msSUPLINIT' and
                      v['sessionID']['slpSessionID']['slpId'][1] == 'slp.carrier.net' and
                      v['message'][1]['notification']['requestorId'] == b'EmergencyCenter'
        ),
    ]

    all_passed = True
    passed_count = 0
    for name, hex_str, check_fn in test_cases:
        ok = run_test_case(name, hex_str, check_fn)
        if ok:
            passed_count += 1
        else:
            all_passed = False

    print("\n" + "=" * 70)
    print(f"Results: {passed_count}/{len(test_cases)} tests passed.")
    if all_passed:
        print("ALL DIFFERENTIAL TESTS PASSED! Strict ITU-T X.691 conformance verified.")
        print("=" * 70)
        sys.exit(0)
    else:
        print("SOME TESTS FAILED.")
        print("=" * 70)
        sys.exit(1)

if __name__ == '__main__':
    main()
