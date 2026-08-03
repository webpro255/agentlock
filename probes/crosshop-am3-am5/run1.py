from probe_crosshop import *

print("=" * 72)
print("SECTION 1a: ORDERING / SELF-LINKING")
print("=" * 72)
report("benign, linker B, MATCH-then-WRITE", benign_session(), linker_B, write_before_match=False)
report("benign, linker B, WRITE-then-MATCH", benign_session(), linker_B, write_before_match=True)
report("echo chain, linker B, MATCH-then-WRITE", echo_session(), linker_B, write_before_match=False)
report("echo chain, linker B, WRITE-then-MATCH", echo_session(), linker_B, write_before_match=True)

print()
print("=" * 72)
print("SECTION 1b/1c: OVER-LINKING AND DENSITY")
print("=" * 72)
report("benign only (no untrusted), linker A", benign_session(), linker_A)
report("benign only (no untrusted), linker B", benign_session(), linker_B)
report("MIXED: trusted chain + untrusted page, linker A", mixed_session(), linker_A)
report("MIXED: trusted chain + untrusted page, linker B", mixed_session(), linker_B)
