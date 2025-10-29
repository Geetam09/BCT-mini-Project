# storage.py
import json
import os
from typing import Any

def load_json(path: str, default: Any):
    if not os.path.exists(path):
        # create file with default content
        with open(path, "w") as f:
            json.dump(default, f, indent=2)
        return default
    with open(path, "r") as f:
        try:
            return json.load(f)
        except Exception:
            # if corrupted, overwrite with default
            with open(path, "w") as fw:
                json.dump(default, fw, indent=2)
            return default

def save_json(path: str, data: Any):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
