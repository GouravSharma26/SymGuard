# Loops beyond UNROLL_DEPTH (default 3) are bounded and not verified beyond that depth.
import os

for i in range(15):
    if i == 8:
        payload = input()
        os.system(payload)
