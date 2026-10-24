import subprocess
user_arg = input()
# Subprocess list argv without shell=True is immune to shell injection
subprocess.run(["ls", "-l", user_arg])
