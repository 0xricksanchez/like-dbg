#!/usr/bin/env python
import sys
from pathlib import Path


def chunks(blist: bytes, chunk_sz: int):
    bs = list(blist)
    for i in range(0, len(bs), chunk_sz):
        yield bs[i : i + chunk_sz]


def chunk_printer(chunk: list[int]):
    res = ", ".join(hex(x) for x in chunk)
    print(f"{res},")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        exit(-1)

    b = Path(sys.argv[1])
    if not b.exists():
        print(f"Binary ({b}) does not exist...")
        exit(-1)

    for c in chunks(b.read_bytes(), 12):
        chunk_printer(c)


if __name__ == "__main__":
    main()
