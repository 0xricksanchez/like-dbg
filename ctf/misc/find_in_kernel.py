#!/usr/bin/env python
import sys
from pathlib import Path

from pwn import ELF, context


@context.quietfunc
def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <vmlinux> <search>")
        print(f'  e.g.: {sys.argv[0]} ctf/vmlinux "/sbin/modprobe"')
        exit(-1)

    kern = sys.argv[1]
    query = sys.argv[2]
    if not Path(kern).exists():
        print(f"Kernel ({kern}) does not exist")
        exit(-1)

    kern = ELF(kern)
    try:
        res = [hex(v - 0xFFFFFFFF81000000) for v in kern.search(f"{query}\0".encode())]
    except StopIteration:
        res = None
    if res:
        print(f"Found @ offset(s) {res}")
    else:
        print("Could not find search term in kernel.")


if __name__ == "__main__":
    main()
