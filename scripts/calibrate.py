"""Print semantic scores for the labeled test prompts, to help tune thresholds.

Run from the project root:   python scripts/calibrate.py

Good thresholds sit between the two groups:
  - flag  threshold: below most ATTACK scores, above most BENIGN scores
  - block threshold: higher, where you're confident it's an attack
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.normalize import variants  # noqa: E402
from app.semantic import SemanticDetector  # noqa: E402
from tests.test_detector import BENIGN, SEMANTIC_ATTACKS  # noqa: E402

det = SemanticDetector()
print(f"backend={det.backend.name}  thresholds={det.thresholds}\n")
print(f"{'label':7} {'attack':>7} {'benign':>7} {'gap':>7}  {'closest family':26} prompt")

rows = []
for label, prompts in (("ATTACK", SEMANTIC_ATTACKS), ("BENIGN", BENIGN)):
    for p in prompts:
        s = det.score(variants(p))
        rows.append((label, s.attack_score))
        print(f"{label:7} {s.attack_score:7.3f} {s.benign_score:7.3f} {s.attack_score - s.benign_score:7.3f}  "
              f"{s.family:26} {p[:60]}")

atk = [s for lab, s in rows if lab == "ATTACK"]
ben = [s for lab, s in rows if lab == "BENIGN"]
print(f"\nlowest attack score:  {min(atk):.3f}")
print(f"highest benign score: {max(ben):.3f}")
if min(atk) > max(ben):
    print(f"clean separation -> a flag threshold around {(min(atk) + max(ben)) / 2:.2f} works for this set")
else:
    print("groups overlap -> the benign/attack gap check and more signatures/anchors have to do the work")
