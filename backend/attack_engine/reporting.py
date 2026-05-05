from __future__ import annotations

import base64
import io
from typing import Any

from fastapi import Response

from backend.attack_engine.analysis import analyze_payload
from backend.attack_engine.schemas import AnalyzeRequest


def report_json_payload(payload: AnalyzeRequest) -> dict[str, Any]:
    analysis = analyze_payload(payload)
    return {"network": payload.network.model_dump(), "analysis": analysis.model_dump()}


def report_pdf_response(payload: AnalyzeRequest) -> Response:
    analysis = analyze_payload(payload)
    lines = [
        f"Algorithm: {analysis.algorithm.value.upper()}",
        f"Entry point: {analysis.selected_entry}",
        f"Critical asset: {analysis.selected_critical_asset}",
        f"Risk score: {analysis.risk_score}/100",
        f"Path: {' -> '.join(analysis.path) if analysis.path else 'No path found'}",
        "",
        "Findings:",
        *analysis.findings,
        "",
        "Step-by-step path:",
        *[
            f"{step.index + 1}. {step.label} ({step.type})"
            + (f" via {step.edge_label}, CVSS {step.cvss}" if step.edge_label else "")
            for step in analysis.steps
        ],
    ]
    pdf = minimal_pdf("Automated Breach Path Report", lines)
    encoded_name = base64.urlsafe_b64encode(b"breach-path-report.pdf").decode()
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=breach-path-report.pdf; filename*=UTF-8''{encoded_name}"},
    )


def minimal_pdf(title: str, lines: list[str]) -> bytes:
    stream = io.BytesIO()
    objects: list[bytes] = []
    content_lines = ["BT", "/F1 18 Tf", "50 770 Td", f"({escape_pdf(title)}) Tj", "/F1 10 Tf", "0 -28 Td"]
    for line in lines:
        content_lines.append(f"({escape_pdf(line[:105])}) Tj")
        content_lines.append("0 -16 Td")
    content_lines.append("ET")
    content = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append(f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"\nendstream")

    stream.write(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(stream.tell())
        stream.write(f"{index} 0 obj\n".encode())
        stream.write(obj)
        stream.write(b"\nendobj\n")

    xref = stream.tell()
    stream.write(f"xref\n0 {len(objects) + 1}\n".encode())
    stream.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        stream.write(f"{offset:010d} 00000 n \n".encode())
    stream.write(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode())
    return stream.getvalue()


def escape_pdf(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
