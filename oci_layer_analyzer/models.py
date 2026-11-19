"""Data models: image manifests, layer descriptors, and per-layer entries."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

FILE = "file"
DIRECTORY = "dir"
SYMLINK = "symlink"
HARDLINK = "hardlink"
WHITEOUT = "whiteout"
OPAQUE_WHITEOUT = "opaque_whiteout"
OTHER = "other"

WHITEOUT_PREFIX = ".wh."
OPAQUE_WHITEOUT_NAME = ".wh..wh..opq"


@dataclass
class LayerDescriptor:
    """Layer description taken from the image manifest."""

    diff_id: str
    compressed_digest: str = ""
    compressed_size: int = 0
    tar_path: str = ""

    @classmethod
    def from_dict(cls, data: Dict) -> "LayerDescriptor":
        return cls(
            diff_id=data.get("diff_id", ""),
            compressed_digest=data.get("compressed_digest", ""),
            compressed_size=int(data.get("compressed_size", 0) or 0),
            tar_path=data.get("tar_path", ""),
        )


@dataclass
class ImageManifest:
    """One image: a name plus its ordered layer list."""

    name: str
    layers: List[LayerDescriptor] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict) -> "ImageManifest":
        return cls(
            name=data.get("name", ""),
            layers=[LayerDescriptor.from_dict(d) for d in data.get("layers", [])],
        )


@dataclass
class FileEntry:
    """A single entry inside a layer. digest is set for regular files only."""

    path: str
    kind: str
    size: int = 0
    digest: Optional[str] = None
    link_target: Optional[str] = None


@dataclass
class UnsafeItem:
    """An entry that must not take part in dedup (e.g. path traversal)."""

    path: str
    reason: str


@dataclass
class LayerIndex:
    """Parsed result for one layer."""

    descriptor: LayerDescriptor
    entries: List[FileEntry] = field(default_factory=list)
    unsafe: List[UnsafeItem] = field(default_factory=list)
    error: Optional[str] = None
    computed_diff_id: Optional[str] = None
    tar_size: int = 0
    data_size: int = 0  # total bytes of regular file content

    @property
    def ok(self) -> bool:
        return self.error is None

    def regular_files(self) -> List[FileEntry]:
        return [e for e in self.entries if e.kind == FILE]
