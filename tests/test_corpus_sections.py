import copy

import pytest

from corpus import CorpusError, extract_html_sections, extract_markdown_sections


MARKDOWN = """\
# File Upload Cheat Sheet

## File Upload Protection

### Filename Safety
Reject path separators in untrusted file names.

#### Nested Detail
Canonicalize a path before enforcing its base-directory boundary.

### Upload and Download Limits
Bound archive extraction size and file count.

## Java Code Snippets
Use `ZipInputStream` with a validated destination path.
"""


def section(path: list[str]) -> dict[str, object]:
    return {"section_path": path}


def test_extracts_exact_heading_path_and_line_range() -> None:
    extracted = extract_markdown_sections(
        MARKDOWN,
        [section(["File Upload Protection", "Filename Safety"])],
    )

    assert extracted == [{
        "section_path": ["File Upload Protection", "Filename Safety"],
        "source_line_start": 5,
        "source_line_end": 9,
        "text": (
            "### Filename Safety\n"
            "Reject path separators in untrusted file names.\n"
            "\n"
            "#### Nested Detail\n"
            "Canonicalize a path before enforcing its base-directory boundary."
        ),
    }]


def test_selected_sections_preserve_declared_order() -> None:
    extracted = extract_markdown_sections(
        MARKDOWN,
        [
            section(["Java Code Snippets"]),
            section(["File Upload Protection", "Upload and Download Limits"]),
        ],
    )

    assert [item["section_path"] for item in extracted] == [
        ["Java Code Snippets"],
        ["File Upload Protection", "Upload and Download Limits"],
    ]
    assert extracted[0]["source_line_start"] == 14
    assert extracted[0]["source_line_end"] == 15
    assert extracted[1]["source_line_start"] == 11
    assert extracted[1]["source_line_end"] == 12


def test_missing_heading_path_raises_corpus_error() -> None:
    with pytest.raises(
        CorpusError,
        match=r"section path not found: File Upload Protection > Missing Section",
    ):
        extract_markdown_sections(
            MARKDOWN,
            [section(["File Upload Protection", "Missing Section"])],
        )


def test_ambiguous_heading_path_raises_corpus_error() -> None:
    ambiguous = """\
# Guide

## Protection

### Validation
First section.

### Validation
Second section.
"""

    with pytest.raises(
        CorpusError,
        match=r"section path is ambiguous: Protection > Validation",
    ):
        extract_markdown_sections(
            ambiguous,
            [section(["Protection", "Validation"])],
        )


def test_extraction_is_deterministic_and_does_not_mutate_raw_text() -> None:
    raw = copy.deepcopy(MARKDOWN)
    selected = [
        section(["File Upload Protection", "Filename Safety"]),
        section(["Java Code Snippets"]),
    ]

    first = extract_markdown_sections(raw, selected)
    second = extract_markdown_sections(raw, selected)

    assert raw == MARKDOWN
    assert first == second


HTML = """\
<!doctype html>
<html><body>
  <h1>Path operations</h1>
  <h2>Normalize a Path</h2>
  <p>Normalize removes redundant name elements.</p>
  <h3>Symbolic links</h3>
  <p>Normalize alone does not resolve symbolic links.</p>
  <h2>Convert a Path</h2>
  <p>toRealPath resolves links on the file system.</p>
</body></html>
"""


def test_extracts_html_heading_section_with_nested_content() -> None:
    extracted = extract_html_sections(
        HTML,
        [section(["Normalize a Path"])],
    )

    assert extracted == [{
        "section_path": ["Normalize a Path"],
        "source_line_start": 4,
        "source_line_end": 7,
        "text": (
            "## Normalize a Path\n"
            "Normalize removes redundant name elements.\n"
            "### Symbolic links\n"
            "Normalize alone does not resolve symbolic links."
        ),
    }]


def test_html_missing_or_ambiguous_heading_is_rejected() -> None:
    with pytest.raises(CorpusError, match=r"section path not found: Missing"):
        extract_html_sections(HTML, [section(["Missing"])])

    ambiguous = "<h1>Guide</h1><h2>Validation</h2><p>A</p><h2>Validation</h2><p>B</p>"
    with pytest.raises(CorpusError, match=r"section path is ambiguous: Validation"):
        extract_html_sections(ambiguous, [section(["Validation"])])


def test_html_extraction_is_deterministic() -> None:
    selected = [section(["Normalize a Path"]), section(["Convert a Path"])]
    assert extract_html_sections(HTML, selected) == extract_html_sections(HTML, selected)


def test_html_with_unclosed_heading_is_rejected() -> None:
    with pytest.raises(CorpusError, match="unclosed heading"):
        extract_html_sections("<h1>Guide</h1><h2>Validation", [section(["Validation"])])
