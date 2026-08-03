from probe_crosshop import *
from agentlock.context import _encoded_scan_needles, _scan_encoding
from agentlock.context import (_SCAN_FLOORS, _SCAN_KINDS, _ENCODED_MIN_LEN,
                               _encoded_scan_forms, _plain_qualifies)

print("="*72); print("SECTION 2: DO THE FAMILY-2 FLOORS TRANSFER TO LINKING?"); print("="*72)
print(f"  _SCAN_FLOORS={_SCAN_FLOORS}  _SCAN_KINDS={sorted(_SCAN_KINDS)}  _ENCODED_MIN_LEN={_ENCODED_MIN_LEN}")

print("\n  (a) which tokens does the shared extractor admit at min_len=6?")
probe_words = ["report", "totals", "summary", "assigned.", "resolved.",
               "escalated.", "details.", "priority", "q3-2026", "2026-03-14",
               "ticket-88213", "evil.com", "abcde", "localhost", "confirmation"]
for w in probe_words:
    toks = sorted(extract_lineage_tokens(w, 6))
    print(f"      {w:<14} -> {toks}")

print("\n  (b) direction-(A) needle sets: do the floors/curation gate them?")
for content, tag in [(UNTRUSTED_PAGE, "untrusted page"),
                     (REPORT, "benign report (DERIVED under linker B)")]:
    n = _encoded_scan_needles(content, 6)
    print(f"      {tag}: {len(n)} needles")
    for x in sorted(n):
        print(f"          {_scan_encoding(x):<7} len={len(x):<3} {x[:60]!r}")

print("\n  (c) a short/undistinctive token: is it excluded from LINKING the")
print("      same way it is excluded from MATCHING?")
for w in ["po-42", "abcde", "report", "evil.co"]:
    print(f"      {w:<10} extract={sorted(extract_lineage_tokens(w,6))} "
          f"plain_qualifies={_plain_qualifies(w,6)} scan_forms={sorted(_encoded_scan_forms(w))}")

print("\n  (d) FALSE-LINK SURFACE from the str kind: how many tokens does an")
print("      ordinary English tool output emit at min_len=6?")
for content, tag in [(REPORT, "REPORT"), (UNTRUSTED_PAGE, "UNTRUSTED_PAGE")]:
    toks = sorted(extract_lineage_tokens(content, 6))
    strs = [t for k, t in toks if k == "str"]
    print(f"      {tag}: {len(toks)} tokens, {len(strs)} of kind 'str'")
    print(f"          str tokens: {strs}")
