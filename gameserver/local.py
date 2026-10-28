"""Resolve the selected runtime without embedding allocation paths in scripts."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def local_settings():
    path=ROOT/'gameserver/local.json'
    return json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}


def runtime_file(name,explicit=None):
    if explicit is not None:return Path(explicit)
    selected=Path(local_settings().get('active_runtime','gameserver/runtime-sla'))
    return (selected if selected.is_absolute() else ROOT/selected)/name
