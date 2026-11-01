"""Command line: `python -m paca bench | demo <ID> [defence] | list`."""
from __future__ import annotations

import sys

HELP = "usage: python -m paca bench [out_dir] | demo <ID> [none|filter|rbac|sandbox|paca] | list"


def main(argv=None) -> int:
    a = list(sys.argv[1:] if argv is None else argv)
    if not a or a[0] in ("-h", "--help"):
        print(HELP); return 0
    from .bench import DEFENCES, main as bench_main
    from .harness import REGISTRY, run
    if a[0] == "bench":
        bench_main(a[1] if len(a) > 1 else "docs"); return 0
    if a[0] == "list":
        for s in REGISTRY:
            print(f"{s.id}  [{s.kind:6}] {s.title}")
        return 0
    if a[0] == "demo" and len(a) > 1:
        sc = next((s for s in REGISTRY if s.id == a[1].upper()), None)
        fac = {k: f for k, _, f in DEFENCES}.get(a[2] if len(a) > 2 else "paca")
        if not sc or not fac:
            print(HELP); return 1
        o = run(sc, fac)
        print(f"{sc.id} {sc.title}\n  {sc.summary}\n")
        for e in o.trace:
            if e["kind"] == "act":
                tag = "EXECUTED" if e["executed"] else e["verdict"].upper()
                print(f"  {e['action']:15} {tag}{' (ATTACKER EFFECT)' if e['executed'] and e['evil'] else ''}")
                for c in e["checks"]:
                    print(f"      {c['id']}: {c['msg']}")
            else:
                print(f"  - {e['kind']}: {str(e.get('text') or e.get('name') or e.get('key'))[:90]}")
        print(f"\n  attacker goal achieved: {o.harmed}" if sc.kind == "attack" else f"\n  task completed: {o.completed}")
        return 0
    print(HELP); return 1


if __name__ == "__main__":
    raise SystemExit(main())
