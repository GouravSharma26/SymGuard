buffer = [0, 1, 2, 3, 4]     # length 5, tracked symbolically by the analyzer

idx = int(input("Enter index: "))

# VULNERABLE: no bounds check at all before indexing with tainted `idx`.
value = buffer[idx]
print(value)

safe_buffer = [10, 20, 30]

idx2 = int(input("Enter another index: "))

# SAFE: guarded by an explicit bounds check on both ends, so the ONLY
# path that reaches the index expression already constrains
# 0 <= idx2 < len(safe_buffer) -- Z3 will prove the OOB condition is UNSAT.
if idx2 >= 0:
    if idx2 < len(safe_buffer):
        value2 = safe_buffer[idx2]
        print(value2)
