#!/usr/bin/env python3
"""
Validation des bibliothèques de formes publiées pour Vista.

Le script part de index.json, ouvre chaque fichier ZIP référencé et vérifie
qu'il est exploitable et sans danger pour l'application :
- structure de l'archive (entrées à la racine, extensions autorisées, limites
  de taille pour se prémunir des « zip bombs ») ;
- manifest.json cohérent avec l'index (identifiant, version) ;
- chaque stencil XML (structure attendue, SVG lisible) ;
- sécurité des SVG : liste blanche d'éléments, aucun script, aucun gestionnaire
  d'événement, aucune ressource externe, aucune déclaration DTD.

Lorsqu'une référence de base est fournie (--base), le script compare aussi le
contenu des archives avec cette référence : il exige une nouvelle version pour
toute bibliothèque modifiée et produit un récapitulatif des formes ajoutées,
supprimées ou modifiées, pour faciliter la relecture d'une pull request.

Les messages sont en anglais : ils sont lus par les contributeurs dans les
journaux de l'intégration continue.

Utilisation :
    python .github/scripts/validate_stencils.py [--base <git ref>] [--summary <file>] [--preview <file>]

Code de retour 1 si au moins une erreur est détectée.
"""

import argparse
import base64
import hashlib
import html
import io
import json
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

# Racine du dépôt, deux niveaux au-dessus de .github/scripts
ROOT = Path(__file__).resolve().parents[2]
INDEX_NAME = "index.json"
STENCILS_FOLDER = "stencils"
MANIFEST_NAME = "manifest.json"

ID_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
VERSION_PATTERN = re.compile(r"^\d+\.\d+(\.\d+)?$")
CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Limites de l'archive : une bibliothèque de formes reste un petit fichier
MAX_ZIP_SIZE = 20 * 1024 * 1024
MAX_ENTRY_COUNT = 5000
MAX_ENTRY_SIZE = 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_SIZE = 50 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100

# Fichiers acceptés dans une archive, en plus de manifest.json
ALLOWED_ENTRY_EXTENSIONS = {".xml", ".md"}

# Éléments SVG autorisés : formes, dégradés, masques et filtres simples.
# Tout élément absent de cette liste (script, foreignObject, image, a, animate...) est refusé.
ALLOWED_SVG_ELEMENTS = {
    "svg", "g", "defs", "symbol", "use", "title", "desc", "metadata", "style",
    "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
    "text", "tspan", "textPath",
    "linearGradient", "radialGradient", "stop", "pattern", "clipPath", "mask", "marker",
    "filter", "feBlend", "feColorMatrix", "feComponentTransfer", "feComposite",
    "feFlood", "feGaussianBlur", "feMerge", "feMergeNode", "feMorphology", "feOffset",
    "feFuncR", "feFuncG", "feFuncB", "feFuncA", "feDropShadow",
}

# Contenu d'élément ignoré : les métadonnées (RDF, par exemple) ne sont pas rendues
IGNORED_SUBTREES = {"metadata"}

# Motifs dangereux dans les attributs de style et les éléments <style>
DANGEROUS_STYLE_PATTERN = re.compile(r"@import|expression\s*\(|javascript:|behavior\s*:|-moz-binding", re.IGNORECASE)
CSS_URL_PATTERN = re.compile(r"url\s*\(\s*['\"]?\s*([^)'\"\s]*)", re.IGNORECASE)

_errors: list[str] = []
_warnings: list[str] = []


def error(message: str) -> None:
    _errors.append(message)


def warn(message: str) -> None:
    _warnings.append(message)


# ---------------------------------------------------------------------------
# Accès aux fichiers (copie de travail ou référence git de base)
# ---------------------------------------------------------------------------

def read_worktree(relative_path: str) -> bytes | None:
    path = ROOT / relative_path
    return path.read_bytes() if path.is_file() else None


def read_git(ref: str, relative_path: str) -> bytes | None:
    """Contenu d'un fichier à une référence git donnée, ou None s'il n'y existe pas."""
    result = subprocess.run(
        ["git", "show", f"{ref}:{relative_path}"],
        cwd=ROOT, capture_output=True, check=False)
    return result.stdout if result.returncode == 0 else None


def git_ref_exists(ref: str) -> bool:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        cwd=ROOT, capture_output=True, check=False)
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------

def parse_version(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def check_text(value, label: str, required: bool = True, max_length: int = 200) -> bool:
    if value is None and not required:
        return True

    if not isinstance(value, str) or not value.strip():
        error(f"{label}: must be a non-empty string")
        return False

    if value != value.strip():
        error(f"{label}: must not start or end with spaces")
    if CONTROL_CHARS_PATTERN.search(value):
        error(f"{label}: must not contain control characters")
    if len(value) > max_length:
        error(f"{label}: must not exceed {max_length} characters")
    return True


def check_https_url(value, label: str) -> None:
    if value is None:
        return

    if not isinstance(value, str):
        error(f"{label}: must be a string")
        return

    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname:
        error(f"{label}: must be an absolute https:// address ({value})")
    elif parts.username or parts.password:
        error(f"{label}: must not contain credentials ({value})")


def load_index(data: bytes | None, label: str) -> list[dict] | None:
    if data is None:
        error(f"{label}: file not found")
        return None

    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as ex:
        error(f"{label}: invalid JSON ({ex})")
        return None

    if not isinstance(document, dict) or not isinstance(document.get("stencils"), list):
        error(f"{label}: must be an object with a 'stencils' array")
        return None

    return document["stencils"]


@dataclass
class IndexEntry:
    id: str
    name: str
    file: str
    version: str
    shapes_count: int | None
    size: int | None


def validate_index() -> list[IndexEntry]:
    items = load_index(read_worktree(INDEX_NAME), INDEX_NAME)
    if items is None:
        return []

    entries: list[IndexEntry] = []
    seen_ids: set[str] = set()
    seen_files: set[str] = set()
    allowed_keys = {"id", "name", "description", "file", "version", "shapesCount", "size", "sourceUrl"}

    for position, item in enumerate(items):
        label = f"{INDEX_NAME} > stencils[{position}]"
        if not isinstance(item, dict):
            error(f"{label}: must be an object")
            continue

        label = f"{INDEX_NAME} > {item.get('id', f'stencils[{position}]')}"

        for key in item:
            if key not in allowed_keys:
                warn(f"{label}: unknown property '{key}' is ignored by the application")

        library_id = item.get("id")
        if not isinstance(library_id, str) or not ID_PATTERN.match(library_id):
            error(f"{label}: 'id' must contain lowercase letters, digits and dashes (e.g. 'google-cloud')")
            continue
        if library_id in seen_ids:
            error(f"{label}: duplicate id '{library_id}'")
        seen_ids.add(library_id)

        check_text(item.get("name"), f"{label} > name", max_length=80)
        check_text(item.get("description"), f"{label} > description", required=False, max_length=300)
        check_https_url(item.get("sourceUrl"), f"{label} > sourceUrl")

        version = item.get("version")
        if not isinstance(version, str) or not VERSION_PATTERN.match(version):
            error(f"{label}: 'version' is required and must look like '1.0' or '1.0.0'")
            version = None

        file = item.get("file")
        if not isinstance(file, str) or not file.startswith(f"{STENCILS_FOLDER}/") or not file.lower().endswith(".zip"):
            error(f"{label}: 'file' must be a .zip file in the '{STENCILS_FOLDER}/' folder")
            continue
        if "/" in file[len(STENCILS_FOLDER) + 1:] or "\\" in file or ".." in file:
            error(f"{label}: 'file' must be directly in the '{STENCILS_FOLDER}/' folder")
            continue
        if file.lower() in seen_files:
            error(f"{label}: file '{file}' is referenced twice")
        seen_files.add(file.lower())

        if not (ROOT / file).is_file():
            error(f"{label}: file '{file}' not found")
            continue

        shapes_count = item.get("shapesCount")
        if shapes_count is not None and (not isinstance(shapes_count, int) or isinstance(shapes_count, bool) or shapes_count < 0):
            error(f"{label}: 'shapesCount' must be a positive integer")
            shapes_count = None

        size = item.get("size")
        if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 0):
            error(f"{label}: 'size' must be a positive integer")
            size = None

        if version is not None and isinstance(item.get("name"), str):
            entries.append(IndexEntry(library_id, item["name"], file, version, shapes_count, size))

    return entries


def report_orphan_files(entries: list[IndexEntry]) -> None:
    referenced = {entry.file.lower() for entry in entries}
    folder = ROOT / STENCILS_FOLDER
    if not folder.is_dir():
        return

    for path in sorted(folder.glob("*.zip")):
        relative = f"{STENCILS_FOLDER}/{path.name}"
        if relative.lower() not in referenced:
            warn(f"{relative}: file is not referenced by {INDEX_NAME} and will never be offered in Vista")


# ---------------------------------------------------------------------------
# Contenu des archives
# ---------------------------------------------------------------------------

@dataclass
class Stencil:
    entry: str
    name: str
    svg: str
    digest: str


@dataclass
class ArchiveContent:
    manifest: dict | None = None
    stencils: dict[str, Stencil] = field(default_factory=dict)
    # Empreinte de chaque entrée : sert à détecter une modification indépendamment de la recompression
    digests: dict[str, str] = field(default_factory=dict)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def check_style(value: str, label: str) -> None:
    if DANGEROUS_STYLE_PATTERN.search(value):
        error(f"{label}: style contains a forbidden construct (@import, expression, javascript:...)")

    for target in CSS_URL_PATTERN.findall(value):
        if not target.startswith("#"):
            error(f"{label}: style references an external resource ({target or 'empty url()'}); only internal references like url(#id) are allowed")


def check_svg(svg_text: str, label: str) -> bool:
    """Vérifie qu'un SVG est lisible et ne contient que des éléments de dessin inoffensifs."""
    if "<!DOCTYPE" in svg_text or "<!ENTITY" in svg_text:
        error(f"{label}: SVG must not contain DOCTYPE or ENTITY declarations")
        return False

    try:
        root = ET.fromstring(svg_text)
    except ET.ParseError as ex:
        error(f"{label}: SVG is not well-formed ({ex})")
        return False

    if local_name(root.tag) != "svg":
        error(f"{label}: SVG root element must be <svg>, found <{local_name(root.tag)}>")
        return False

    valid = True

    def visit(element: ET.Element) -> None:
        nonlocal valid
        name = local_name(element.tag)

        if name not in ALLOWED_SVG_ELEMENTS:
            error(f"{label}: SVG element <{name}> is not allowed")
            valid = False
            return

        for attribute, value in element.attrib.items():
            attribute_name = local_name(attribute).lower()
            if attribute_name.startswith("on"):
                error(f"{label}: event handler attribute '{attribute_name}' is not allowed on <{name}>")
                valid = False
            elif attribute_name == "href" and not value.strip().startswith("#"):
                error(f"{label}: <{name}> references an external resource ({value[:60]}); only internal references like #id are allowed")
                valid = False
            elif attribute_name == "style" or "url(" in value.lower():
                before = len(_errors)
                check_style(value, f"{label} > <{name}> {attribute_name}")
                valid = valid and len(_errors) == before

        if name == "style":
            before = len(_errors)
            check_style(element.text or "", f"{label} > <style>")
            valid = valid and len(_errors) == before

        if name in IGNORED_SUBTREES:
            return

        for child in element:
            visit(child)

    visit(root)
    return valid


def read_stencil(data: bytes, label: str) -> tuple[str, str] | None:
    """Lit un stencil XML et retourne son nom et son SVG."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        error(f"{label}: file must be UTF-8 encoded")
        return None

    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        error(f"{label}: XML must not contain DOCTYPE or ENTITY declarations")
        return None

    try:
        root = ET.fromstring(text)
    except ET.ParseError as ex:
        error(f"{label}: XML is not well-formed ({ex}); check that '&', '<' and '>' are escaped in texts")
        return None

    if root.tag != "Stencil":
        error(f"{label}: root element must be <Stencil>, found <{root.tag}>")
        return None

    name = (root.findtext("Name") or "").strip()
    svg = (root.findtext("Svg") or "").strip()

    if not name:
        error(f"{label}: <Name> is missing or empty")
    if not svg:
        error(f"{label}: <Svg> is missing or empty")
    if not name or not svg:
        return None

    for child in root:
        if child.tag not in {"Name", "DefaultText", "Description", "Svg"}:
            warn(f"{label}: element <{child.tag}> is ignored by the application")

    if not check_svg(svg, label):
        return None

    return name, svg


def read_archive(data: bytes, label: str, report: bool = True) -> ArchiveContent | None:
    """
    Ouvre une archive et contrôle son contenu. Avec report=False (version de base d'une pull request),
    les anomalies ne sont pas signalées : seul le contenu est extrait pour la comparaison.
    """
    global _errors, _warnings
    saved = (_errors, _warnings)
    if not report:
        _errors, _warnings = [], []

    try:
        return _read_archive(data, label)
    finally:
        if not report:
            _errors, _warnings = saved


def _read_archive(data: bytes, label: str) -> ArchiveContent | None:
    if len(data) > MAX_ZIP_SIZE:
        error(f"{label}: archive exceeds {MAX_ZIP_SIZE // (1024 * 1024)} MB")
        return None

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as ex:
        error(f"{label}: not a valid ZIP archive ({ex})")
        return None

    content = ArchiveContent()

    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ENTRY_COUNT:
            error(f"{label}: archive contains more than {MAX_ENTRY_COUNT} entries")
            return None

        total_size = sum(info.file_size for info in infos)
        if total_size > MAX_TOTAL_UNCOMPRESSED_SIZE:
            error(f"{label}: uncompressed content exceeds {MAX_TOTAL_UNCOMPRESSED_SIZE // (1024 * 1024)} MB")
            return None

        seen_names: set[str] = set()
        stencil_names: dict[str, str] = {}

        for info in infos:
            entry = info.filename
            entry_label = f"{label} > {entry}"

            if info.is_dir():
                error(f"{entry_label}: folders are not allowed, all files must be at the root of the archive")
                continue
            if "/" in entry or "\\" in entry or ".." in entry or entry.startswith(("/", "~")) or ":" in entry:
                error(f"{entry_label}: files must be at the root of the archive (no folder, no relative or absolute path)")
                continue
            if CONTROL_CHARS_PATTERN.search(entry):
                error(f"{entry_label}: file name must not contain control characters")
                continue
            if entry.lower() in seen_names:
                error(f"{entry_label}: duplicate file name in the archive")
                continue
            seen_names.add(entry.lower())

            if info.flag_bits & 0x1:
                error(f"{entry_label}: encrypted files are not allowed")
                continue
            if info.file_size > MAX_ENTRY_SIZE:
                error(f"{entry_label}: file exceeds {MAX_ENTRY_SIZE // 1024} KB once uncompressed")
                continue
            if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                error(f"{entry_label}: suspicious compression ratio (possible zip bomb)")
                continue

            extension = Path(entry).suffix.lower()
            if entry != MANIFEST_NAME and extension not in ALLOWED_ENTRY_EXTENSIONS:
                error(f"{entry_label}: file type '{extension or '(none)'}' is not allowed; only {MANIFEST_NAME}, .xml stencils and .md notes are accepted")
                continue

            try:
                entry_data = archive.read(info)
            except (zipfile.BadZipFile, NotImplementedError, OSError) as ex:
                error(f"{entry_label}: file cannot be read ({ex})")
                continue

            content.digests[entry] = hashlib.sha256(entry_data).hexdigest()

            if entry == MANIFEST_NAME:
                content.manifest = read_manifest(entry_data, entry_label)
            elif extension == ".xml":
                stencil = read_stencil(entry_data, entry_label)
                if stencil is not None:
                    name, svg = stencil
                    if name.lower() in stencil_names:
                        warn(f"{entry_label}: shape name '{name}' is also used by '{stencil_names[name.lower()]}'")
                    stencil_names[name.lower()] = entry
                    content.stencils[entry] = Stencil(entry, name, svg, content.digests[entry])

        if MANIFEST_NAME not in seen_names:
            error(f"{label}: {MANIFEST_NAME} is missing at the root of the archive")
        if not content.stencils:
            error(f"{label}: archive does not contain any valid stencil")

    return content


def read_manifest(data: bytes, label: str) -> dict | None:
    try:
        manifest = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as ex:
        error(f"{label}: invalid JSON ({ex})")
        return None

    if not isinstance(manifest, dict):
        error(f"{label}: must be a JSON object")
        return None

    if not isinstance(manifest.get("internalId"), str) or not ID_PATTERN.match(manifest["internalId"]):
        error(f"{label}: 'internalId' must contain lowercase letters, digits and dashes")
    check_text(manifest.get("displayName"), f"{label} > displayName", max_length=80)
    if not isinstance(manifest.get("version"), str) or not VERSION_PATTERN.match(manifest["version"]):
        error(f"{label}: 'version' must look like '1.0' or '1.0.0'")

    return manifest


def check_consistency(entry: IndexEntry, content: ArchiveContent, size: int) -> None:
    label = f"{INDEX_NAME} > {entry.id}"
    manifest = content.manifest or {}

    if manifest.get("internalId") not in (None, entry.id):
        error(f"{label}: id '{entry.id}' differs from internalId '{manifest['internalId']}' in {entry.file}")
    if manifest.get("version") not in (None, entry.version):
        error(f"{label}: version '{entry.version}' differs from version '{manifest['version']}' in {entry.file}")
    if isinstance(manifest.get("displayName"), str) and manifest["displayName"] != entry.name:
        warn(f"{label}: name '{entry.name}' differs from displayName '{manifest['displayName']}' shown in the shapes panel")
    if entry.size is not None and entry.size != size:
        error(f"{label}: size is {entry.size} but {entry.file} is {size} bytes")
    if entry.shapes_count is not None and entry.shapes_count != len(content.stencils):
        error(f"{label}: shapesCount is {entry.shapes_count} but {entry.file} contains {len(content.stencils)} valid stencil(s)")


# ---------------------------------------------------------------------------
# Comparaison avec la référence de base et récapitulatif
# ---------------------------------------------------------------------------

@dataclass
class LibraryChange:
    entry: IndexEntry
    status: str  # "new", "updated", "unchanged"
    previous_version: str | None = None
    added: list[Stencil] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[Stencil] = field(default_factory=list)
    other_files: list[str] = field(default_factory=list)


def compare_with_base(base: str, entries: list[IndexEntry], contents: dict[str, ArchiveContent]) -> tuple[list[LibraryChange], list[str]]:
    base_index = read_git(base, INDEX_NAME)
    base_items = load_index(base_index, f"{INDEX_NAME} ({base})") if base_index is not None else []
    base_by_id = {item.get("id"): item for item in base_items or [] if isinstance(item, dict)}

    changes: list[LibraryChange] = []
    for entry in entries:
        content = contents.get(entry.id)
        if content is None:
            continue

        base_item = base_by_id.get(entry.id)
        base_data = read_git(base, base_item["file"]) if base_item and isinstance(base_item.get("file"), str) else None
        base_content = read_archive(base_data, f"{base_item['file']} ({base})", report=False) if base_data else None

        if base_content is None:
            changes.append(LibraryChange(entry, "new", added=sorted(content.stencils.values(), key=lambda s: s.name.lower())))
            continue

        if content.digests == base_content.digests:
            changes.append(LibraryChange(entry, "unchanged"))
            continue

        change = LibraryChange(entry, "updated", previous_version=(base_content.manifest or {}).get("version"))
        for name, stencil in content.stencils.items():
            previous = base_content.stencils.get(name)
            if previous is None:
                change.added.append(stencil)
            elif previous.digest != stencil.digest:
                change.modified.append(stencil)
        change.removed = sorted(base_content.stencils[name].name for name in base_content.stencils if name not in content.stencils)
        change.other_files = sorted(
            name for name in set(content.digests) | set(base_content.digests)
            if name not in content.stencils and name not in base_content.stencils
            and content.digests.get(name) != base_content.digests.get(name))
        change.added.sort(key=lambda s: s.name.lower())
        change.modified.sort(key=lambda s: s.name.lower())
        changes.append(change)

        previous_version = change.previous_version
        if isinstance(previous_version, str) and VERSION_PATTERN.match(previous_version) \
                and parse_version(entry.version) <= parse_version(previous_version):
            error(f"{INDEX_NAME} > {entry.id}: content of {entry.file} changed, its version must be increased (currently {entry.version}, was {previous_version})")

    current_ids = {entry.id for entry in entries}
    removed_libraries = sorted(str(item.get("name", library_id)) for library_id, item in base_by_id.items() if library_id not in current_ids)
    return changes, removed_libraries


def write_summary(path: Path, changes: list[LibraryChange], removed_libraries: list[str], base: str | None) -> None:
    lines = ["# Shape libraries validation", ""]

    if _errors:
        lines += [f"❌ **{len(_errors)} error(s)**, {len(_warnings)} warning(s).", ""]
        lines += ["<details open><summary>Errors</summary>", "", *[f"- {html.escape(m)}" for m in _errors], "", "</details>", ""]
    else:
        lines += [f"✅ **Validation passed**, {len(_warnings)} warning(s).", ""]

    if _warnings:
        lines += ["<details><summary>Warnings</summary>", "", *[f"- {html.escape(m)}" for m in _warnings], "", "</details>", ""]

    if base is not None:
        lines += [f"## Changes compared with `{base}`", ""]
        changed = [c for c in changes if c.status != "unchanged"]
        if not changed and not removed_libraries:
            lines += ["No shape library content changed.", ""]

        for change in changed:
            entry = change.entry
            if change.status == "new":
                lines += [f"### 🆕 {html.escape(entry.name)} `{entry.id}` — version {entry.version}", "",
                          f"New library, {len(change.added)} shape(s).", ""]
            else:
                lines += [f"### ✏️ {html.escape(entry.name)} `{entry.id}` — version {change.previous_version} → {entry.version}", "",
                          f"{len(change.added)} added, {len(change.modified)} modified, {len(change.removed)} removed.", ""]
            for title, names in (("Added", [s.name for s in change.added]),
                                 ("Modified", [s.name for s in change.modified]),
                                 ("Removed", change.removed),
                                 ("Other files changed", change.other_files)):
                if names:
                    lines += [f"<details><summary>{title} ({len(names)})</summary>", "",
                              *[f"- {html.escape(n)}" for n in names], "", "</details>", ""]

        for name in removed_libraries:
            lines += [f"### 🗑️ {html.escape(name)} — removed from the index", ""]

        if changed:
            lines += ["Download the **stencils-preview** artifact of this run to review the added and modified shapes visually.", ""]

    path.write_text("\n".join(lines), encoding="utf-8")


def write_preview(path: Path, changes: list[LibraryChange]) -> None:
    """
    Page HTML de relecture des formes ajoutées ou modifiées. Chaque SVG, déjà validé, est affiché
    au travers d'une balise <img> : un navigateur n'exécute jamais de script dans ce contexte.
    """
    sections = []
    for change in changes:
        shapes = change.added + change.modified
        if not shapes:
            continue

        cards = []
        for stencil in shapes:
            status = "added" if stencil in change.added else "modified"
            data = base64.b64encode(stencil.svg.encode("utf-8")).decode("ascii")
            cards.append(
                f'<figure class="{status}"><img alt="" src="data:image/svg+xml;base64,{data}">'
                f'<figcaption>{html.escape(stencil.name)}<small>{status} · {html.escape(stencil.entry)}</small></figcaption></figure>')

        sections.append(f"<h2>{html.escape(change.entry.name)} <small>{html.escape(change.entry.id)} · {change.entry.version}</small></h2>"
                        f'<div class="grid">{"".join(cards)}</div>')

    body = "".join(sections) or "<p>No added or modified shape.</p>"
    path.write_text(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Shape libraries preview</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">
<style>
body{{font-family:system-ui,sans-serif;margin:24px;background:#f6f7f9;color:#1f2328}}
h2 small,figcaption small{{display:block;color:#656d76;font-weight:normal;font-size:12px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px}}
figure{{margin:0;background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:12px;text-align:center}}
figure.added{{border-color:#1a7f37}} figure.modified{{border-color:#9a6700}}
img{{width:96px;height:96px;object-fit:contain}}
figcaption{{font-size:13px;margin-top:8px;word-break:break-word}}
</style></head><body><h1>Shape libraries preview</h1>{body}</body></html>
""", encoding="utf-8")


# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Vista shape libraries.")
    parser.add_argument("--base", help="git reference to compare with (e.g. origin/main)")
    parser.add_argument("--summary", help="write a Markdown summary to this file (e.g. $GITHUB_STEP_SUMMARY)")
    parser.add_argument("--preview", help="write an HTML preview of added and modified shapes to this file")
    args = parser.parse_args()

    entries = validate_index()
    report_orphan_files(entries)

    contents: dict[str, ArchiveContent] = {}
    for entry in entries:
        data = read_worktree(entry.file)
        content = read_archive(data, entry.file)
        if content is not None:
            contents[entry.id] = content
            check_consistency(entry, content, len(data))

    base = args.base
    if base is not None and not git_ref_exists(base):
        warn(f"base reference '{base}' not found, changes are not compared")
        base = None

    changes, removed_libraries = compare_with_base(base, entries, contents) if base else ([], [])

    for message in _warnings:
        print(f"warning: {message}")
    for message in _errors:
        print(f"error: {message}")

    total_shapes = sum(len(c.stencils) for c in contents.values())
    print()
    print(f"{len(entries)} library(ies), {total_shapes} shape(s), {len(_errors)} error(s), {len(_warnings)} warning(s).")

    if args.summary:
        write_summary(Path(args.summary), changes, removed_libraries, base)
    if args.preview:
        write_preview(Path(args.preview), changes)

    if _errors:
        print("Shape libraries validation failed.")
        return 1

    print("Shape libraries validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
