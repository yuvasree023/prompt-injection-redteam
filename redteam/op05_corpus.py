"""Build attack corpora for OP-05: byte-identical copies of the shipped
Season-1 corpus, plus attacker-controlled documents for the poisoned variant.

The poisoned docs get proper manifest entries (sha256 over their text bytes)
and passages.jsonl rows so corpus validation passes cleanly - the attack
assumes the attacker can add well-formed documents to the corpus, not that
they can corrupt it.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path


def render_text(doc):
    parts = []
    for i, sec in enumerate(doc["sections"]):
        parts.append(f"[{doc['doc_id']}#s{i:05d}]\n{sec}")
    return "\n".join(parts) + "\n"


def build(base_corpus: Path, out_dir: Path, poison_docs=()) -> Path:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    shutil.copytree(base_corpus, out_dir)
    if not poison_docs:
        return out_dir
    with (out_dir / "manifest.jsonl").open("a", encoding="utf-8") as mf, \
         (out_dir / "passages.jsonl").open("a", encoding="utf-8") as pf:
        for d in poison_docs:
            text = render_text(d)
            (out_dir / "text" / f"{d['doc_id']}.txt").write_text(text, encoding="utf-8")
            sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
            mf.write(json.dumps({
                "doc_id": d["doc_id"], "title": d["title"],
                "source_url": "redteam://attacker-controlled",
                "effective_date": "2020-01-01", "supersedes": [], "role": "public",
                "text_path": f"text/{d['doc_id']}.txt", "sha256": sha}) + "\n")
            for i, sec in enumerate(d["sections"]):
                pf.write(json.dumps({"passage_id": f"{d['doc_id']}#s{i:05d}",
                                     "doc_id": d["doc_id"], "text": sec}) + "\n")
    return out_dir
