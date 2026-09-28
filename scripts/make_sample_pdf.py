"""Write the demo sample PDF to disk: python scripts/make_sample_pdf.py [out.pdf]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from app.services.sample import build  # noqa: E402

target = Path(sys.argv[1] if len(sys.argv) > 1 else "samples/classified_memo.pdf")
target.parent.mkdir(parents=True, exist_ok=True)
target.write_bytes(build())
print(target)
