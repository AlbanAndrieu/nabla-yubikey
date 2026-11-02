"""Load a probe script (hyphenated, not importable by name) as a module for hermetic tests."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts/workstation"
sys.path.insert(0, str(SCRIPTS))  # probes import probe_common from their own directory


def load_probe(filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(filename.removesuffix(".py").replace("-", "_"),
                                                  SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
