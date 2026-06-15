from pathlib import Path
import re

from pydantic import BaseModel, Field


HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
FENCE_PATTERN = re.compile(r"^(```|~~~)\s*([A-Za-z0-9_+.-]*)\s*$")
LINK_PATTERN = re.compile(r"\[([^\]\n]+)\]\(([^)\s]+)\)")
ENV_VAR_PATTERN = re.compile(
    r"(?:\$\{?|\bprocess\.env\.|\benv:)?\b([A-Z][A-Z0-9_]{2,})\b"
)


class MarkdownHeading(BaseModel):
    level: int = Field(ge=1, le=6)
    text: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class MarkdownParagraph(BaseModel):
    text: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class MarkdownCodeBlock(BaseModel):
    language: str | None = None
    text: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class MarkdownLink(BaseModel):
    label: str
    url: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class MarkdownEnvVarMention(BaseModel):
    name: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class ParsedMarkdownArtifact(BaseModel):
    path: str | None = None
    headings: list[MarkdownHeading] = Field(default_factory=list)
    paragraphs: list[MarkdownParagraph] = Field(default_factory=list)
    code_blocks: list[MarkdownCodeBlock] = Field(default_factory=list)
    links: list[MarkdownLink] = Field(default_factory=list)
    env_vars: list[MarkdownEnvVarMention] = Field(default_factory=list)


def parse_markdown_text(text: str, *, path: str | None = None) -> ParsedMarkdownArtifact:
    artifact = ParsedMarkdownArtifact(path=path)
    lines = text.splitlines()
    paragraph_lines: list[str] = []
    paragraph_start_line: int | None = None
    in_code_block = False
    code_fence = ""
    code_language: str | None = None
    code_lines: list[str] = []
    code_start_line = 0

    for index, line in enumerate(lines, start=1):
        fence_match = FENCE_PATTERN.match(line)
        if in_code_block:
            _extract_inline_metadata(line, index, artifact)
            if fence_match and fence_match.group(1) == code_fence:
                artifact.code_blocks.append(
                    MarkdownCodeBlock(
                        language=code_language,
                        text="\n".join(code_lines),
                        start_line=code_start_line,
                        end_line=index,
                    )
                )
                in_code_block = False
                code_fence = ""
                code_language = None
                code_lines = []
                code_start_line = 0
            else:
                code_lines.append(line)
            continue

        if fence_match:
            _flush_paragraph(paragraph_lines, paragraph_start_line, index - 1, artifact)
            paragraph_lines = []
            paragraph_start_line = None
            in_code_block = True
            code_fence = fence_match.group(1)
            code_language = fence_match.group(2) or None
            code_start_line = index
            _extract_inline_metadata(line, index, artifact)
            continue

        heading_match = HEADING_PATTERN.match(line)
        if heading_match:
            _flush_paragraph(paragraph_lines, paragraph_start_line, index - 1, artifact)
            paragraph_lines = []
            paragraph_start_line = None
            artifact.headings.append(
                MarkdownHeading(
                    level=len(heading_match.group(1)),
                    text=heading_match.group(2).strip(),
                    start_line=index,
                    end_line=index,
                )
            )
            _extract_inline_metadata(line, index, artifact)
            continue

        if not line.strip():
            _flush_paragraph(paragraph_lines, paragraph_start_line, index - 1, artifact)
            paragraph_lines = []
            paragraph_start_line = None
            continue

        if paragraph_start_line is None:
            paragraph_start_line = index
        paragraph_lines.append(line.strip())
        _extract_inline_metadata(line, index, artifact)

    final_line = len(lines)
    if in_code_block:
        artifact.code_blocks.append(
            MarkdownCodeBlock(
                language=code_language,
                text="\n".join(code_lines),
                start_line=code_start_line,
                end_line=max(final_line, code_start_line),
            )
        )
    else:
        _flush_paragraph(paragraph_lines, paragraph_start_line, final_line, artifact)

    return artifact


def parse_markdown_file(path: str | Path) -> ParsedMarkdownArtifact:
    markdown_path = Path(path)
    return parse_markdown_text(markdown_path.read_text(encoding="utf-8"), path=str(markdown_path))


def _flush_paragraph(
    paragraph_lines: list[str],
    start_line: int | None,
    end_line: int,
    artifact: ParsedMarkdownArtifact,
) -> None:
    if not paragraph_lines or start_line is None:
        return
    artifact.paragraphs.append(
        MarkdownParagraph(
            text=" ".join(paragraph_lines).strip(),
            start_line=start_line,
            end_line=end_line,
        )
    )


def _extract_inline_metadata(line: str, line_number: int, artifact: ParsedMarkdownArtifact) -> None:
    for label, url in LINK_PATTERN.findall(line):
        artifact.links.append(MarkdownLink(label=label, url=url, start_line=line_number, end_line=line_number))

    seen_names = {mention.name for mention in artifact.env_vars if mention.start_line == line_number}
    for name in ENV_VAR_PATTERN.findall(line):
        if _looks_like_env_var(name) and name not in seen_names:
            artifact.env_vars.append(MarkdownEnvVarMention(name=name, start_line=line_number, end_line=line_number))
            seen_names.add(name)


def _looks_like_env_var(name: str) -> bool:
    return "_" in name or name.endswith(("KEY", "TOKEN", "SECRET", "PASSWORD", "URL", "HOST"))
