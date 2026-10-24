# Regex string constraints are not translated into SMT theory;
# conditions with re.match/re.fullmatch are explored as unmodeled branches.
import os
import re

cmd = input()
if re.fullmatch(r"[a-zA-Z0-9_-]+", cmd):
    os.system("echo " + cmd)
