"""Generate docs/ops.md from the operation schema."""

from __future__ import annotations

import html
import json
import re
import unicodedata
from pathlib import Path
from typing import Any


ROOT = Path(__file__).parent.parent
SCHEMA_PATH = ROOT / "ida_cyberchef" / "data" / "operation_schema.json"
DOCS_PATH = ROOT / "docs" / "ops.md"
UNSUPPORTED_OPERATION_NOTES = {
    "JavaScript Beautify": "Unsupported in the current STPyV8 runtime. Excluded by the current Node-targeted bundle.",
    "JavaScript Minify": "Unsupported in the current STPyV8 runtime. Excluded by the current Node-targeted bundle.",
    "JavaScript Parser": "Unsupported in the current STPyV8 runtime. Excluded by the current Node-targeted bundle.",
    "Syntax highlighter": "Unsupported in the current STPyV8 runtime. Excluded by the current Node-targeted bundle.",
    "DNS over HTTPS": "Unsupported in the current STPyV8 runtime. Requires browser-style request APIs and live network access.",
    "HTTP request": "Unsupported in the current STPyV8 runtime. Requires browser-style request APIs and live network access.",
    "Optical Character Recognition": "Unsupported in the current STPyV8 runtime. Requires browser workers and OCR assets that this project does not provide.",
    "Add Text To Image": "Unsupported in the current STPyV8 runtime. Requires browser-style asset loading that this project does not provide.",
    "Magic": "Unsupported in the current STPyV8 runtime.",
    "YARA Rules": "Unsupported in the current STPyV8 runtime.",
    "Argon2": "Unsupported in the current STPyV8 runtime.",
    "Argon2 compare": "Unsupported in the current STPyV8 runtime.",
}



def render_method_name(operation_name: str) -> str:
    """Return the function-style name used in docs/ops.md."""
    normalized = unicodedata.normalize("NFKD", operation_name)
    ascii_name = "".join(char for char in normalized if not unicodedata.combining(char))
    words = re.findall(r"[A-Za-z0-9]+", ascii_name)
    rendered_words = [word if word.isupper() else word[:1].upper() + word[1:] for word in words]
    return "".join(rendered_words)



def render_literal(value: Any) -> str:
    """Render a schema value for markdown output."""
    if value is None:
        return "null"
    if isinstance(value, str):
        escaped = value.encode("unicode_escape").decode("ascii")
        return escaped.replace("\\u2019", "’")
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)



def clean_html_description(description: str) -> str:
    """Convert CyberChef HTML descriptions into plain markdown-ish text."""
    text = description.replace("<br><br>", "\n\n").replace("<br>", "\n")
    text = re.sub(r"<code>(.*?)</code>", r"`\1`", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()



def extract_option_label(option: Any) -> str:
    """Return a display label for an option-like schema entry."""
    if isinstance(option, dict):
        return str(option.get("name", option.get("value", "")))
    return str(option)



def format_arg(arg: dict[str, Any]) -> str:
    """Format one argument definition for markdown."""
    name = str(arg.get("name", ""))
    arg_type = str(arg.get("type", ""))
    value = arg.get("value")

    if isinstance(value, list) and arg_type in {
        "option",
        "editableOption",
        "editableOptionShort",
        "argSelector",
        "populateMultiOption",
    }:
        labels = [f"`{extract_option_label(option)}`" for option in value[:3]]
        summary = ", ".join(labels)
        if len(value) > 3:
            summary += f" (+{len(value) - 3} more)"
        if "defaultIndex" in arg and value:
            default_index = int(arg.get("defaultIndex", 0))
            default_label = extract_option_label(value[min(default_index, len(value) - 1)])
            summary += f"; default `{default_label}`"
        return f"  - **{name}** ({arg_type}): {summary}"

    if value not in (None, "", []) or arg_type in {"boolean", "number", "string", "binaryString", "binaryShortString", "toggleString"}:
        return f"  - **{name}** ({arg_type}): default `{render_literal(value)}`"

    return f"  - **{name}** ({arg_type})"



def get_support_annotation(operation_name: str) -> str | None:
    """Return the user-facing support note for an operation, if any."""
    return UNSUPPORTED_OPERATION_NOTES.get(operation_name)



def generate_operation_doc(operation: dict[str, Any]) -> str:
    """Generate markdown for one operation."""
    name = str(operation.get("name", ""))
    lines = [f"### `{render_method_name(name)}()`", "", f"**Operation:** `{name}`", ""]

    category = operation.get("category")
    if category:
        lines.append(f"**Category:** `{category}`")
        lines.append("")

    module = operation.get("module", "Unknown")
    lines.append(f"**Module:** {module}")
    lines.append("")

    if support_note := get_support_annotation(name):
        lines.append(f"**Support:** {support_note}")
        lines.append("")

    description = clean_html_description(str(operation.get("description", "")))
    if description:
        lines.append(description)
        lines.append("")

    if info_url := operation.get("infoURL"):
        lines.append(f"[More info]({info_url})")
        lines.append("")

    lines.append(
        f"**Input:** `{operation.get('inputType', 'unknown')}` → **Output:** `{operation.get('outputType', 'unknown')}`"
    )
    lines.append("")

    args = operation.get("args", [])
    if args:
        lines.append("**Arguments:**")
        lines.extend(format_arg(arg) for arg in args)
        lines.append("")

    lines.append("---")
    lines.append("")
    return "\n".join(lines)



def generate_docs_markdown(schema: dict[str, Any]) -> str:
    """Render the full operations reference markdown document."""
    operations = sorted(schema.get("operations", []), key=lambda operation: str(operation.get("name", "")))
    lines = [
        "# CyberChef Operations Reference",
        "",
        f"This document lists all {len(operations)} available CyberChef operations.",
        "",
        "Unsupported operations shipped in the current runtime remain listed here and are annotated per operation.",
        "See the Runtime support section in `readme.md` for the broader support policy.",
        "",
        "## Operations",
        "",
    ]

    for operation in operations:
        lines.append(generate_operation_doc(operation))

    return "\n".join(lines)



def main() -> None:
    schema = json.loads(SCHEMA_PATH.read_text())
    DOCS_PATH.write_text(generate_docs_markdown(schema))
    print(f"Documentation generated: {DOCS_PATH}")
    print(f"Operations documented: {len(schema.get('operations', []))}")


if __name__ == "__main__":
    main()
