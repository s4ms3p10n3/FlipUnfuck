#!/usr/bin/env python3
"""
Back up and restore the two regions the duress-PIN patch destroys.

  flash          - dump internal flash page 0 (0x08000000, vector table +
                    reset stub) via GDB over the Black Magic Probe
  sd              - read SD card LBA 0-2047 (MBR / FAT32 VBR / FSInfo /
                    start of both FATs) via a direct block-device read
  all             - both backups, one run
  restore-flash   - write a flash backup back, then read it back and
                    verify it matches byte-for-byte
  restore-sd      - write an SD backup back, then read it back and
                    verify it matches byte-for-byte
  restore-all     - both restores, one run

Usage:
    python3 backup_duress_targets.py flash --port /dev/ttyACM0
    python3 backup_duress_targets.py sd --sd-device /dev/sdb
    python3 backup_duress_targets.py restore-flash --port /dev/ttyACM0
    python3 backup_duress_targets.py restore-sd --sd-device /dev/sdb
"""

import argparse
import hashlib
import shutil
import struct
import subprocess
import sys
from pathlib import Path

DEFAULT_GDB = "arm-none-eabi-gdb"
DEFAULT_FLASH_ADDR = 0x08000000
DEFAULT_FLASH_SIZE = 0x1000  # one WB55 flash page — matches furi_hal_flash_erase(0)
SD_SECTOR_SIZE = 512
DEFAULT_SD_SECTOR_COUNT = 2048  # LBA 0-2047 — matches the duress wipe range
DEFAULT_FLASH_FILE = "vector_table_backup.bin"
DEFAULT_SD_FILE = "sd_boot_region_backup.bin"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------
# flash: BMP is a GDB remote-serial-protocol server. "issuing commands" to
# it means driving gdb, same as you would interactively — this shells out
# to gdb in batch mode with the same monitor/attach/dump sequence you'd
# type by hand.
# --------------------------------------------------------------------------
def backup_flash(args):
    gdb = args.gdb or shutil.which(DEFAULT_GDB) or DEFAULT_GDB
    out = Path(args.flash_out)
    start, end = args.flash_addr, args.flash_addr + args.flash_size

    batch = [
        "-nx", "--batch",
        "-ex", "set confirm off",
        "-ex", f"target extended-remote {args.port}",
        "-ex", "monitor swdp_scan",
        "-ex", f"attach {args.attach_index}",
        "-ex", f"dump binary memory {out} {start:#010x} {end:#010x}",
        "-ex", "detach",
    ]

    print(f"[flash] {gdb} -> {args.port}, attach {args.attach_index}, "
          f"dumping {args.flash_size:#x} bytes @ {start:#010x}")
    try:
        result = subprocess.run([gdb, *batch], capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        sys.exit(f"[flash] '{gdb}' not found — pass --gdb, or check "
                  f"toolchain/*/bin/arm-none-eabi-gdb under your fbt checkout.")
    except subprocess.TimeoutExpired:
        sys.exit("[flash] gdb didn't respond within 60s — probe not attached, "
                  "wrong --port, or the target isn't powered.")

    print(result.stdout)
    if result.returncode != 0 or not out.exists():
        print(result.stderr, file=sys.stderr)
        sys.exit("[flash] dump failed — check the `monitor swdp_scan` output "
                  "above for the right --attach-index. The WB55 is dual-core; "
                  "make sure you attached the CM4 app core, not the CM0/BLE one.")

    size = out.stat().st_size
    print(f"[flash] wrote {size} bytes to {out}  sha256={sha256_of(out)}")
    if size >= 8:
        with open(out, "rb") as f:
            sp, reset_vec = struct.unpack_from("<II", f.read(8))
        print(f"[flash]   initial SP    = {sp:#010x}")
        print(f"[flash]   reset handler = {reset_vec:#010x}  "
              f"(odd address expected — Thumb bit set)")


def restore_flash(args):
    gdb = args.gdb or shutil.which(DEFAULT_GDB) or DEFAULT_GDB
    src = Path(args.flash_in)
    if not src.exists():
        sys.exit(f"[restore-flash] {src} not found.")
    addr = args.flash_addr
    size = src.stat().st_size

    batch = [
        "-nx", "--batch",
        "-ex", "set confirm off",
        "-ex", f"target extended-remote {args.port}",
        "-ex", "monitor swdp_scan",
        "-ex", f"attach {args.attach_index}",
        "-ex", f"restore {src} binary {addr:#010x}",
        "-ex", "detach",
    ]

    print(f"[restore-flash] {gdb} -> {args.port}, attach {args.attach_index}, "
          f"writing {src} ({size} bytes) @ {addr:#010x}")
    try:
        result = subprocess.run([gdb, *batch], capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        sys.exit(f"[restore-flash] '{gdb}' not found — pass --gdb.")
    except subprocess.TimeoutExpired:
        sys.exit("[restore-flash] gdb didn't respond within 60s.")

    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit("[restore-flash] write failed — see gdb output above. Do not "
                  "assume the device is in a known state; re-run `flash` to see "
                  "what's actually there before doing anything else.")

    print("[restore-flash] write finished — reading it back to verify...")
    verify_out = src.with_name(src.stem + ".verify.bin")
    verify_args = argparse.Namespace(
        port=args.port, gdb=args.gdb, attach_index=args.attach_index,
        flash_addr=addr, flash_size=size, flash_out=str(verify_out),
    )
    backup_flash(verify_args)

    if sha256_of(verify_out) == sha256_of(src):
        print("[restore-flash] VERIFIED — device now matches the backup exactly.")
    else:
        sys.exit("[restore-flash] MISMATCH — device contents do not match the "
                  "backup after writing. Do not trust this recovery and do not "
                  "reset the device yet; investigate before doing anything else.")


# --------------------------------------------------------------------------
# sd: NOT a BMP/SWD job. The card isn't memory-mapped into the STM32's
# address space GDB can `dump` from — reaching it over SWD would mean
# calling into furi_hal_sd_read_blocks() live on the halted target and
# reading the result back out of RAM, which is slow (one probe round-trip
# per register poke) and depends on firmware internals I can't verify from
# here. Pull the card and read/write it as a plain block device instead —
# same end result, far more reliable.
# --------------------------------------------------------------------------
def backup_sd(args):
    out = Path(args.sd_out)
    total_bytes = args.sd_sector_count * SD_SECTOR_SIZE

    print(f"[sd] reading {args.sd_sector_count} sectors "
          f"({total_bytes} bytes) from {args.sd_device}")
    try:
        with open(args.sd_device, "rb") as dev, open(out, "wb") as f:
            remaining = total_bytes
            while remaining > 0:
                chunk = dev.read(min(1 << 20, remaining))
                if not chunk:
                    sys.exit("[sd] short read — got fewer bytes than expected. "
                              "Wrong device, or the card is smaller than "
                              f"{args.sd_sector_count} sectors?")
                f.write(chunk)
                remaining -= len(chunk)
    except PermissionError:
        sys.exit(f"[sd] permission denied on {args.sd_device} — raw block "
                  f"reads need elevation: sudo on Linux/macOS; on Windows, "
                  f"run as Administrator against \\\\.\\PhysicalDriveN and "
                  f"make sure the volume isn't mounted/in use first.")

    print(f"[sd] wrote {total_bytes} bytes to {out}  sha256={sha256_of(out)}")
    if total_bytes >= 512:
        with open(out, "rb") as f:
            boot_sector = f.read(512)
        print(f"[sd]   55AA boot signature present: {boot_sector[510:512] == b'\\x55\\xaa'}")


def restore_sd(args):
    src = Path(args.sd_in)
    if not src.exists():
        sys.exit(f"[restore-sd] {src} not found.")
    total_bytes = src.stat().st_size

    print(f"[restore-sd] writing {total_bytes} bytes to {args.sd_device}")
    try:
        with open(src, "rb") as f, open(args.sd_device, "r+b") as dev:
            remaining = total_bytes
            while remaining > 0:
                chunk = f.read(min(1 << 20, remaining))
                dev.write(chunk)
                remaining -= len(chunk)
            dev.flush()
    except PermissionError:
        sys.exit(f"[restore-sd] permission denied on {args.sd_device} — same "
                  f"elevation rules as the backup direction.")

    print("[restore-sd] write finished — reading it back to verify...")
    with open(args.sd_device, "rb") as dev:
        check = dev.read(total_bytes)
    if hashlib.sha256(check).hexdigest() == sha256_of(src):
        print("[restore-sd] VERIFIED — card now matches the backup exactly.")
    else:
        sys.exit("[restore-sd] MISMATCH — card contents do not match the backup "
                  "after writing. Investigate before trusting this card.")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_flash_args(sp, restore=False):
        sp.add_argument("--port", required=True, help="BMP GDB serial port, e.g. /dev/ttyACM0 or COM5")
        sp.add_argument("--gdb", default=None, help=f"gdb binary (default: {DEFAULT_GDB} on PATH)")
        sp.add_argument("--attach-index", type=int, default=1,
                         help="target index from `monitor swdp_scan` (default 1 — verify it's the CM4)")
        sp.add_argument("--flash-addr", type=lambda x: int(x, 0), default=DEFAULT_FLASH_ADDR)
        if restore:
            sp.add_argument("--flash-in", default=DEFAULT_FLASH_FILE,
                             help=f"backup file to write back (default {DEFAULT_FLASH_FILE})")
        else:
            sp.add_argument("--flash-size", type=lambda x: int(x, 0), default=DEFAULT_FLASH_SIZE,
                             help="bytes to dump (default one page, 0x1000 — bump this for a full firmware backup)")
            sp.add_argument("--flash-out", default=DEFAULT_FLASH_FILE)

    def add_sd_args(sp, restore=False):
        sp.add_argument("--sd-device", required=True,
                         help=r"raw block device: /dev/sdb (Linux), /dev/rdiskN (macOS), \\.\PhysicalDriveN (Windows)")
        if restore:
            sp.add_argument("--sd-in", default=DEFAULT_SD_FILE,
                             help=f"backup file to write back (default {DEFAULT_SD_FILE})")
        else:
            sp.add_argument("--sd-sector-count", type=int, default=DEFAULT_SD_SECTOR_COUNT)
            sp.add_argument("--sd-out", default=DEFAULT_SD_FILE)

    pf = sub.add_parser("flash", help="dump the internal flash vector table via BMP/gdb")
    add_flash_args(pf)
    pf.set_defaults(func=backup_flash)

    ps = sub.add_parser("sd", help="read the SD card boot region from a card reader")
    add_sd_args(ps)
    ps.set_defaults(func=backup_sd)

    pa = sub.add_parser("all", help="run both backups")
    add_flash_args(pa)
    add_sd_args(pa)
    pa.set_defaults(func=lambda a: (backup_flash(a), backup_sd(a)))

    prf = sub.add_parser("restore-flash", help="write a flash backup back via BMP/gdb, then verify")
    add_flash_args(prf, restore=True)
    prf.set_defaults(func=restore_flash)

    prs = sub.add_parser("restore-sd", help="write an SD backup back to a card reader, then verify")
    add_sd_args(prs, restore=True)
    prs.set_defaults(func=restore_sd)

    pra = sub.add_parser("restore-all", help="run both restores")
    add_flash_args(pra, restore=True)
    add_sd_args(pra, restore=True)
    pra.set_defaults(func=lambda a: (restore_flash(a), restore_sd(a)))

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
