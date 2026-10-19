#!/usr/bin/env python
"""Watch metadata-only courses' News pages in Python, retaining only a fingerprint and timestamp."""
import os, pathlib, shutil, sys
_EXT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_EXT / "lib"))
_root = os.environ.get("HERALD_ROOT") or str(pathlib.Path(shutil.which("herald")).resolve().parents[1])
sys.path.insert(0, str(pathlib.Path(_root) / "lib"))
from herald import collector
from canvas_access.sync import collect_news
NAME = "canvas_news"
REQUIRES = ("canvas_api",)
CADENCE_MINUTES = 30
def collect(con):
    return collect_news(con)
if __name__ == "__main__":
    collector.main(NAME, collect)
