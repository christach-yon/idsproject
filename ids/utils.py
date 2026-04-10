from datetime import datetime

def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def safe_getattr(obj, attr, default=None):
    return getattr(obj, attr, default)
