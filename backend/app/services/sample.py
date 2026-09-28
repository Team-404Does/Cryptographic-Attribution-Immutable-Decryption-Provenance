"""Realistic 2-page 'classified' sample PDF used by the demo seed and tests."""
import pymupdf

BODY = (
    "This memorandum summarises the procurement position for the coastal radar "
    "modernisation programme. Vendor shortlisting has concluded and three bids "
    "remain under technical evaluation. The evaluation committee recommends that "
    "the final award be deferred until the independent security audit of the "
    "firmware supply chain is complete. All figures below are provisional and "
    "must not be shared outside the distribution list. Any disclosure of this "
    "document is traceable to the individual decryption session that produced it."
)

ROWS = [
    ("Bidder", "Technical score", "Cost (Cr)", "Status"),
    ("Vendor A", "82 / 100", "412.5", "Under review"),
    ("Vendor B", "77 / 100", "389.0", "Under review"),
    ("Vendor C", "91 / 100", "455.2", "Audit pending"),
]


def build() -> bytes:
    doc = pymupdf.open()
    for pno in range(2):
        page = doc.new_page(width=595, height=842)  # A4 points
        page.insert_text((56, 70), "RESTRICTED - INTERNAL DISTRIBUTION ONLY", fontsize=9, color=(0.7, 0, 0))
        page.insert_text((56, 110), f"Programme Memorandum PM-2026-{17 + pno}", fontsize=18, fontname="hebo")
        page.insert_text((56, 132), "Office of Strategic Procurement", fontsize=11, color=(0.3, 0.3, 0.3))
        rect = pymupdf.Rect(56, 160, 539, 420)
        page.insert_textbox(rect, (BODY + " ") * 2, fontsize=11, lineheight=1.45)
        y = 450
        for i, row in enumerate(ROWS):
            for j, cell in enumerate(row):
                page.insert_text((56 + j * 122, y), cell, fontsize=10.5, fontname="hebo" if i == 0 else "helv")
            page.draw_line((56, y + 6), (539, y + 6), color=(0.75, 0.75, 0.75), width=0.5)
            y += 26
        page.draw_rect(pymupdf.Rect(56, 580, 300, 720), color=(0.2, 0.3, 0.6), fill=(0.9, 0.93, 1.0))
        page.insert_textbox(pymupdf.Rect(66, 592, 290, 710),
                            "Decision required: approve audit extension of 30 days and "
                            "hold contract negotiations.", fontsize=11)
        page.insert_text((56, 800), f"Page {pno + 1} of 2", fontsize=9, color=(0.4, 0.4, 0.4))
    data = doc.tobytes(garbage=3, deflate=True)
    doc.close()
    return data
