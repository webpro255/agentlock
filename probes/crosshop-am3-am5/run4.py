from probe_crosshop import *

print("="*72); print("SECTION 4: THE PAYOFF CHECK (P1 verbatim vs P2 encoded hop)"); print("="*72)
report("P1 verbatim relay, linker A", attack_session_verbatim(), linker_A)
report("P1 verbatim relay, linker B", attack_session_verbatim(), linker_B)

calls, enc = attack_session_b64()
print(f"\n  base64 of the untrusted page ({len(enc)} chars): {enc[:70]}...")
report("P2 base64 hop, linker A", calls, linker_A)
report("P2 base64 hop, linker B", calls, linker_B)

print()
print("="*72)
print("SECTION 4b: WOULD THE SHIPPED SINGLE-HOP CHECK ALREADY DENY AT C?")
print("        (i.e. is the cross-hop link even load-bearing for P2?)")
print("="*72)
for name, sess, sink_params in [
    ("P1 sink send_payment", attack_session_verbatim(),
     {"to": "mallory@evil.com", "memo": "per notice"}),
    ("P2 sink post_webhook", calls, {"payload": enc}),
]:
    tr = ContextTracker()
    sid = "x"
    for c in sess[:-1]:
        tr.record_write(sid, c.source, "h", writer_id=c.tool, tool_name=c.tool,
                        content=c.output)
    out = {}
    m = tr.parameter_lineage_check(sid, sink_params, min_len=6, outcome=out)
    print(f"\n  {name}: shipped param_lineage_check -> "
          f"{'MATCH' if m else 'None'} {out}")
    if m:
        print(f"      cites {m['untrusted_source_ref']} tok={m['matched_token'][:50]!r} "
              f"dir={m.get('match_direction','token(B)')}")

print()
print("="*72)
print("SECTION 4c: DOES THE LINK SURVIVE WHEN THE ENCODED FORM IS THE ONLY")
print("            CARRIER (untrusted content NOT in the sink params)?")
print("="*72)
# The genuinely cross-hop shape: sink param carries ONLY B's output, and B's
# output is an encoding whose plaintext never appears in the sink params.
tr = ContextTracker(); sid = "y"
for c in calls[:-1]:
    tr.record_write(sid, c.source, "h", writer_id=c.tool, tool_name=c.tool, content=c.output)
out = {}
m = tr.parameter_lineage_check(sid, {"payload": enc}, min_len=6, outcome=out)
print(f"  sink params = {{'payload': <base64 blob>}} -> {'MATCH' if m else 'None'} {out}")
if m:
    print(f"      cites {m['untrusted_source_ref']} via {m.get('match_direction','B')} "
          f"tok={m['matched_token'][:40]!r}")
