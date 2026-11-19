"""Safely parse layer tarballs and build a file-level content index.

Safety rules:
- Member names that stay absolute or contain ``..`` after normalization are
  path-traversal risks: they are only recorded, never indexed for dedup.
- A corrupt tar never crashes the analysis; the whole layer is marked
  unusable with a reason.
- Whiteouts (``.wh.`` prefix / ``.wh..wh..opq``) are metadata only and are
  excluded from content dedup.
"""
from __future__ import annotations

import hashlib
import io
import posixpath
import tarfile
from typing import Optional

from .models import (
    DIRECTORY,
    FILE,
    HARDLINK,
    OPAQUE_WHITEOUT,
    OPAQUE_WHITEOUT_NAME,
    OTHER,
    SYMLINK,
    WHITEOUT,
    WHITEOUT_PREFIX,
    FileEntry,
    LayerDescriptor,
    LayerIndex,
    UnsafeItem,
)

_CHUNK = 1024 * 1024


class UnsafePathError(ValueError):
    """Member name is unsafe (absolute path or traversal)."""


def normalize_member_path(name: str) -> str:
    """Normalize a tar member name; raise UnsafePathError when unsafe."""
    if not name:
        raise UnsafePathError("empty path")
    if name.startswith("/") or name.startswith("\\"):
        raise UnsafePathError("absolute path")
    # Check segment by segment so normpath cannot silently swallow traversal.
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UnsafePathError("path traversal ('..' segment)")
    normalized = posixpath.normpath("/".join(parts)) if parts else ""
    if not normalized or normalized == ".":
        raise UnsafePathError("empty path after normalization")
    if normalized.startswith("/") or normalized == ".." or normalized.startswith("../"):
        raise UnsafePathError("path traversal after normalization")
    return normalized


def _sha256_stream(fileobj) -> str:
    digest = hashlib.sha256()
    while True:
        chunk = fileobj.read(_CHUNK)
        if not chunk:
            break
        digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _classify(member: tarfile.TarInfo, normalized: str) -> str:
    base = posixpath.basename(normalized)
    if base == OPAQUE_WHITEOUT_NAME:
        return OPAQUE_WHITEOUT
    if base.startswith(WHITEOUT_PREFIX):
        return WHITEOUT
    if member.isreg():
        return FILE
    if member.isdir():
        return DIRECTORY
    if member.issym():
        return SYMLINK
    if member.islnk():
        return HARDLINK
    return OTHER


def index_layer(descriptor: LayerDescriptor) -> LayerIndex:
    """Read a local layer tar and index it. Errors are recorded, never raised."""
    index = LayerIndex(descriptor=descriptor)
    try:
        with open(descriptor.tar_path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        index.error = "layer read failed: %s" % exc
        return index

    index.tar_size = len(raw)
    index.computed_diff_id = "sha256:" + hashlib.sha256(raw).hexdigest()

    try:
        tar = tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
    except (tarfile.TarError, EOFError, ValueError, OSError) as exc:
        index.error = "corrupt tar: %s" % exc
        return index

    with tar:
        for member in tar:
            name = member.name
            try:
                normalized = normalize_member_path(name)
            except UnsafePathError as exc:
                index.unsafe.append(
                    UnsafeItem(path=name, reason="unsafe path: %s" % exc)
                )
                continue

            kind = _classify(member, normalized)
            entry = FileEntry(path=normalized, kind=kind)

            if kind == FILE:
                try:
                    extracted = tar.extractfile(member)
                except (tarfile.TarError, KeyError, OSError) as exc:
                    index.unsafe.append(
                        UnsafeItem(path=normalized, reason="unreadable member: %s" % exc)
                    )
                    continue
                if extracted is None:
                    index.unsafe.append(
                        UnsafeItem(path=normalized, reason="unreadable member")
                    )
                    continue
                entry.size = member.size
                entry.digest = _sha256_stream(extracted)
                index.data_size += entry.size
            elif kind == HARDLINK:
                # Validate the target now; content is resolved during analysis
                # so that link targets appearing later in the tar still work.
                try:
                    entry.link_target = normalize_member_path(member.linkname)
                except UnsafePathError as exc:
                    index.unsafe.append(
                        UnsafeItem(
                            path=normalized,
                            reason="hardlink target unsafe: %s" % exc,
                        )
                    )
                    continue
            elif kind == SYMLINK:
                entry.link_target = member.linkname

            index.entries.append(entry)

    return index
