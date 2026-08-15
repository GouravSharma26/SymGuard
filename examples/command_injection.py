import os

user_input = input("Enter filename to list: ")

if user_input == "safe_mode":
    # This branch never actually restricts anything -- still concatenates
    # the tainted value into the shell command.
    cmd = "ls " + user_input
    os.system(cmd)
else:
    cmd = "ls " + user_input
    os.system(cmd)
