import time
from contextlib import contextmanager


@contextmanager
def trace_span(name: str):
    start = time.time()
    try:
        yield
    finally:
        elapsed = (time.time() - start) * 1000
        print(f"[TRACE] {name} took {elapsed:.2f}ms")
