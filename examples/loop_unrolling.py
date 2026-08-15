import os

# VULNERABLE: each iteration reads a new tainted filename and immediately
# shells out with it. The loop body is unrolled UNROLL_DEPTH times, so the
# analyzer proves the sink is reachable using the state from iteration 1
# (it doesn't need all 3 unrolled copies to find this -- it's tainted on
# the very first pass already).
for i in range(3):
    filename = input("Enter a filename to archive: ")
    os.system("tar -cf backup.tar " + filename)


# SAFE (within the analyzed depth): the tainted index is always checked
# against the list bounds *inside* the loop body before use, on every
# unrolled iteration, so each of the 3 unrolled copies proves UNSAT for
# the out-of-bounds condition.
inventory = ["pen", "pencil", "eraser"]

count = 0
while count < 3:
    idx = int(input("Pick an item index: "))
    if idx >= 0:
        if idx < len(inventory):
            print(inventory[idx])
    count = count + 1
