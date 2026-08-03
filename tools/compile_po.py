#!/usr/bin/env python3
"""Compile a gettext PO catalog to GNU MO without third-party packages."""

from __future__ import annotations

import ast
import struct
import sys
from pathlib import Path


def quoted(value: str) -> str:
    return ast.literal_eval(value.strip())


def parse_po(path: Path) -> dict[str, str]:
    messages: dict[str, str] = {}
    entry: dict[str, object] = {}
    active: tuple[str, int | None] | None = None
    fuzzy = False

    def flush() -> None:
        nonlocal entry, active, fuzzy
        msgid = str(entry.get("msgid", ""))
        if entry and not fuzzy:
            if "msgid_plural" in entry:
                original = msgid + "\0" + str(entry["msgid_plural"])
                translations = entry.get("msgstr_plural", {})
                assert isinstance(translations, dict)
                translated = "\0".join(
                    str(translations[index]) for index in sorted(translations)
                )
            else:
                original = msgid
                translated = str(entry.get("msgstr", ""))
            context = str(entry.get("msgctxt", ""))
            if context:
                original = context + "\x04" + original
            messages[original] = translated
        entry = {}
        active = None
        fuzzy = False

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            flush()
            continue
        if line.startswith("#," ) and "fuzzy" in line:
            fuzzy = True
            continue
        if line.startswith("#"):
            continue
        if line.startswith("msgctxt "):
            entry["msgctxt"] = quoted(line[8:])
            active = ("msgctxt", None)
        elif line.startswith("msgid_plural "):
            entry["msgid_plural"] = quoted(line[13:])
            active = ("msgid_plural", None)
        elif line.startswith("msgid "):
            entry["msgid"] = quoted(line[6:])
            active = ("msgid", None)
        elif line.startswith("msgstr["):
            end = line.index("]")
            index = int(line[7:end])
            translations = entry.setdefault("msgstr_plural", {})
            assert isinstance(translations, dict)
            translations[index] = quoted(line[end + 1 :])
            active = ("msgstr_plural", index)
        elif line.startswith("msgstr "):
            entry["msgstr"] = quoted(line[7:])
            active = ("msgstr", None)
        elif line.startswith('"') and active is not None:
            addition = quoted(line)
            field, index = active
            if field == "msgstr_plural":
                translations = entry[field]
                assert isinstance(translations, dict) and index is not None
                translations[index] = str(translations[index]) + addition
            else:
                entry[field] = str(entry.get(field, "")) + addition
    flush()
    return messages


def write_mo(messages: dict[str, str], path: Path) -> None:
    pairs = sorted(
        (original.encode("utf-8"), translated.encode("utf-8"))
        for original, translated in messages.items()
    )
    count = len(pairs)
    originals_offset = 28
    translations_offset = originals_offset + count * 8
    strings_offset = translations_offset + count * 8

    originals = bytearray()
    translations = bytearray()
    original_table: list[tuple[int, int]] = []
    translation_table: list[tuple[int, int]] = []

    for original, _ in pairs:
        original_table.append((len(original), strings_offset + len(originals)))
        originals.extend(original + b"\0")
    translations_base = strings_offset + len(originals)
    for _, translated in pairs:
        translation_table.append((len(translated), translations_base + len(translations)))
        translations.extend(translated + b"\0")

    output = bytearray(
        struct.pack(
            "<7I",
            0x950412DE,
            0,
            count,
            originals_offset,
            translations_offset,
            0,
            0,
        )
    )
    for length, offset in original_table + translation_table:
        output.extend(struct.pack("<2I", length, offset))
    output.extend(originals)
    output.extend(translations)
    path.write_bytes(output)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {Path(sys.argv[0]).name} INPUT.po OUTPUT.mo", file=sys.stderr)
        return 2
    source, target = map(Path, sys.argv[1:])
    messages = parse_po(source)
    write_mo(messages, target)
    print(f"Compiled {len(messages)} messages: {source} -> {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
