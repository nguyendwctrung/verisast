import copy

import pytest

from corpus import CorpusError, extract_markdown_sections


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
