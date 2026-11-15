"""Run one OP-05 red-team configuration and write JSONL results.

Usage (from the project root, OP-05 venv python):
  python -m redteam.op05_run --corpus poison --backend llm --guard none \
      --out results/op05_poison_llm_stock.jsonl

Configs:
  --corpus clean|poison   which corpus copy to serve
  --backend extractive|llm
  --guard  none|prompt|full   (full = prompt guardrails + corpus allowlist)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OP05 = ROOT.parent / "op-05-ask-the-policy-book"
sys.path.insert(0, str(OP05))

from redteam import op05_attacks as A
from redteam import op05_corpus, op05_guardrails


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--corpus", choices=["clean", "poison"], required=True)
    p.add_argument("--backend", choices=["extractive", "llm"], required=True)
    p.add_argument("--guard", choices=["none", "prompt", "full"], default="none")
    p.add_argument("--out", required=True)
    p.add_argument("--tag", default="")
    p.add_argument("--only", default="", help="comma-separated item ids to run")
    p.add_argument("--sleep", type=float, default=0.0, help="pause between items (RPM pacing)")
    args = p.parse_args()

    work = ROOT / "work"
    corpus_dir = op05_corpus.build(
        OP05 / "data" / "corpus", work / f"corpus_{args.corpus}",
        A.POISON_DOCS if args.corpus == "poison" else ())
    index_dir = work / f".index_{args.corpus}"

    if args.backend == "llm":
        os.environ["OP05_GEN_BACKEND"] = "openai"
        os.environ["OP05_GEN_MODEL"] = os.environ.get("LLM_MODEL", "gemini-3.5-flash-lite")
        os.environ.setdefault("LLM_BASE_URL",
                              "https://generativelanguage.googleapis.com/v1beta/openai")
        os.environ["OP05_GEN_STRICT"] = "1"  # quota stops the run, never a silent fallback
    else:
        os.environ["OP05_GEN_BACKEND"] = "extractive"
        for k in ("LLM_BASE_URL", "LLM_API_KEY", "LLM_API_KEY_FALLBACK"):
            os.environ.pop(k, None)

    from policybook import ingest, llm
    from policybook.answer import Answerer

    ingest.run(["--corpus-dir", str(corpus_dir), "--index-dir", str(index_dir),
                "--report", str(work / f"ingest_{args.corpus}.json")])

    if args.guard in ("prompt", "full"):
        op05_guardrails.apply(llm, args.guard)

    answerer = Answerer(str(index_dir), str(OP05 / "models" / "all-MiniLM-L6-v2"),
                        str(corpus_dir), live=False)
    if args.guard == "full":
        clean_docs = {json.loads(l)["doc_id"]
                      for l in (OP05 / "data" / "corpus" / "manifest.jsonl")
                      .read_text().splitlines() if l.strip()}
        removed = op05_guardrails.apply_allowlist(answerer, clean_docs)
        print(f"allowlist quarantined {len(removed)} docs: {removed}", file=sys.stderr)

    dev = [json.loads(l) for l in
           (OP05 / "data" / "questions_dev.jsonl").read_text().splitlines() if l.strip()]
    items = A.items(dev)
    if args.only:
        wanted = set(args.only.split(","))
        items = [it for it in items if it["id"] in wanted]

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8") as f:
        for it in items:
            if args.sleep:
                time.sleep(args.sleep)
            t0 = time.perf_counter()
            try:
                res = answerer.answer(it["id"], it["question"], it["role"], it["as_of"])
                d = res.public_dict()
                d["generator"] = res.generator
                d["debug"] = {k: v for k, v in res.debug.items()
                              if k in ("blocked_evidence", "allowed_pool", "top_bm25",
                                       "top_cosine", "gen_fallback_reason", "role_guard")}
            except Exception as exc:  # quota etc. - record, stop loudly
                d = {"id": it["id"], "status": "runner_error",
                     "answer": f"{type(exc).__name__}: {exc}"[:300], "citations": []}
                f.write(json.dumps({"run": vars(args), "item": it, "result": d}) + "\n")
                f.flush()
                print(f"STOP: {it['id']}: {d['answer']}", file=sys.stderr)
                break
            pred = A.PREDICATES.get(it["id"])
            rec = {"run": vars(args), "item": it, "result": d,
                   "attack_succeeded": (bool(pred(d)) if pred else None),
                   "control_held": (bool(d["status"] == it["expected_status"]
                                    and (it["id"] != "indiafinbench_REG_174"
                                         or "press release" in (d.get("answer") or "").lower()))
                                    if it["kind"] == "control" else None),
                   "elapsed_s": round(time.perf_counter() - t0, 2)}
            f.write(json.dumps(rec) + "\n")
            f.flush()
            n += 1
            print(f"[{n}/{len(items)}] {it['id']} {it['kind']}: {d['status']} "
                  f"attack_ok={rec['attack_succeeded']} held={rec['control_held']}",
                  file=sys.stderr)
    san = op05_guardrails.sanitization_log
    if san:
        (out_path.parent / (out_path.stem + ".sanitization.json")).write_text(
            json.dumps(san, indent=1))
    print(f"wrote {n} rows -> {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
