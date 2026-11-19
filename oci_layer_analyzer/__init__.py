"""OCI image layer analyzer: content-based dedup planning across images.

Static planning tool: reads image manifests and local layer tarballs, reports
reusable layers/files, estimated savings, conflicts, and unsafe items. It never
modifies the original images.
"""

from .analyzer import Analyzer, analyze_manifest
from .models import ImageManifest, LayerDescriptor

__all__ = ["Analyzer", "analyze_manifest", "ImageManifest", "LayerDescriptor"]

__version__ = "0.1.0"
