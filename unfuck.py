#!/usr/bin/env python3
"""Flipper De-Fucker - All-in-One Combined Script.

    Combined from:
    - flipper_defucker.py (PyQt5 Designer UI)[cite: 1]
    - backup_duress_targets.py (BMP/SD backup & restore CLI)[cite: 2]
    - Flipper De-Fucker.py (GUI glue & background threading)[cite: 3]

Run:  python flipper_defucker_all_in_one.py
      (Windows: use an Administrator terminal if you want SD card access - raw disks need it.)
Needs Python 3.12+ and: pip install PyQt5
"""

import argparse
import contextlib
import ctypes
import hashlib
import io
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtSerialPort import QSerialPortInfo

WINDOWS = platform.system() == "Windows"
QMessageBox = QtWidgets.QMessageBox


# ===========================================================================
# 1. CLI Backend Logic (adapted from backup_duress_targets.py[cite: 2])
# ===========================================================================

DEFAULT_GDB = "arm-none-eabi-gdb.exe"
DEFAULT_OBJCOPY = "arm-none-eabi-objcopy.exe"
DEFAULT_FLASH_ADDR = 0x08000000
DEFAULT_FLASH_SIZE = 0x1000  # one WB55 flash page — matches furi_hal_flash_erase(0)
SD_SECTOR_SIZE = 512
DEFAULT_SD_SECTOR_COUNT = 2048  # LBA 0-2047 — matches the duress wipe range
DEFAULT_FLASH_FILE = "vector_table_backup.bin"
DEFAULT_SD_FILE = "sd_boot_region_backup.bin"

if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    SCRIPT_DIR = Path(sys._MEIPASS)
else:
    SCRIPT_DIR = Path(__file__).resolve().parent


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_tool(explicit: str | None, tool_name: str) -> str:
    """Resolve a tool from an explicit path, the script's toolchain, then PATH."""
    if explicit:
        p = Path(explicit)
        if p.exists():
            return str(p)
        found = shutil.which(explicit)
        if found:
            return found
        sys.exit(f"[toolchain] '{explicit}' not found.")

    candidates = [
        SCRIPT_DIR / "toolchain" / "x86_64-windows" / "bin" / f"{tool_name}.exe",
        SCRIPT_DIR / "toolchain" / "x86_64-windows" / "bin" / tool_name,
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    found = shutil.which(tool_name)
    if found:
        return found

    sys.exit(
        f"[toolchain] '{tool_name}' not found. Expected it under "
        f"{SCRIPT_DIR / 'toolchain' / 'x86_64-windows' / 'bin'} or on PATH."
    )


def backup_flash(args):
    gdb = resolve_tool(args.gdb, DEFAULT_GDB)
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
        result = subprocess.run(
            [gdb, *batch], capture_output=True, text=True, timeout=60
        )
    except FileNotFoundError:
        sys.exit(f"[flash] '{gdb}' not found — pass --gdb, or check toolchain.")
    except subprocess.TimeoutExpired:
        sys.exit("[flash] gdb didn't respond within 60s — probe not attached, "
                 "wrong --port, or target isn't powered.")

    print(result.stdout)
    if result.returncode != 0 or not out.exists():
        print(result.stderr, file=sys.stderr)
        sys.exit("[flash] dump failed — check `monitor swdp_scan` output.")

    size = out.stat().st_size
    print(f"[flash] wrote {size} bytes to {out}  sha256={sha256_of(out)}")
    if size >= 8:
        with open(out, "rb") as f:
            sp, reset_vec = struct.unpack_from("<II", f.read(8))
        print(f"[flash]   initial SP    = {sp:#010x}")
        print(f"[flash]   reset handler = {reset_vec:#010x}")


def make_flash_elf(src: Path, addr: int, objcopy: str) -> Path:
    raw_elf = src.with_name(src.stem + ".raw.elf")
    flash_elf = src.with_name(src.stem + ".flash.elf")

    for path in (raw_elf, flash_elf):
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    result = subprocess.run(
        [objcopy, "-I", "binary", "-O", "elf32-littlearm", "-B", "arm", str(src), str(raw_elf)],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        sys.exit("[restore-flash] failed to create the ELF wrapper.")

    result = subprocess.run(
        [objcopy, "--change-section-address", f".data={addr:#010x}", str(raw_elf), str(flash_elf)],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        sys.exit("[restore-flash] failed to relocate the ELF section.")

    try:
        raw_elf.unlink()
    except FileNotFoundError:
        pass

    return flash_elf


def restore_flash(args):
    gdb = resolve_tool(args.gdb, DEFAULT_GDB)
    objcopy = resolve_tool(args.objcopy, DEFAULT_OBJCOPY)
    src = Path(args.flash_in)
    if not src.exists():
        sys.exit(f"[restore-flash] {src} not found.")

    addr = args.flash_addr
    size = src.stat().st_size
    if size == 0:
        sys.exit("[restore-flash] backup file is empty.")

    flash_elf = make_flash_elf(src, addr, objcopy)

    batch = [
        "-nx", "--batch",
        "-ex", "set confirm off",
        "-ex", f"target extended-remote {args.port}",
        "-ex", "monitor swdp_scan",
        "-ex", f"attach {args.attach_index}",
        "-ex", f"load {flash_elf}",
        "-ex", "detach",
    ]

    print(f"[restore-flash] programming {src} ({size} bytes) @ {addr:#010x}")
    try:
        result = subprocess.run(
            [gdb, *batch], capture_output=True, text=True, timeout=60
        )
    except FileNotFoundError:
        sys.exit(f"[restore-flash] '{gdb}' not found.")
    except subprocess.TimeoutExpired:
        sys.exit("[restore-flash] gdb didn't respond within 60s.")

    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit("[restore-flash] flash programming failed.")

    for path in (flash_elf, flash_elf.with_name(flash_elf.name.replace(".flash.elf", ".raw.elf"))):
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    print("[restore-flash] write finished — verifying...")
    verify_out = src.with_name(src.stem + ".verify.bin")
    verify_args = argparse.Namespace(
        port=args.port, gdb=args.gdb, attach_index=args.attach_index,
        flash_addr=addr, flash_size=size, flash_out=str(verify_out),
    )
    backup_flash(verify_args)

    if sha256_of(verify_out) == sha256_of(src):
        print("[restore-flash] VERIFIED successfully.")
    else:
        sys.exit("[restore-flash] MISMATCH — device contents do not match backup.")


def backup_sd(args):
    out = Path(args.sd_out)
    total_bytes = args.sd_sector_count * SD_SECTOR_SIZE

    print(f"[sd] reading {args.sd_sector_count} sectors ({total_bytes} bytes) from {args.sd_device}")
    try:
        with open(args.sd_device, "rb") as dev, open(out, "wb") as f:
            remaining = total_bytes
            while remaining > 0:
                chunk = dev.read(min(1 << 20, remaining))
                if not chunk:
                    sys.exit("[sd] short read from SD device.")
                f.write(chunk)
                remaining -= len(chunk)
    except PermissionError:
        sys.exit(f"[sd] permission denied on {args.sd_device} — run as Administrator.")

    print(f"[sd] wrote {total_bytes} bytes to {out} sha256={sha256_of(out)}")


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
                if not chunk:
                    sys.exit("[restore-sd] source backup ended unexpectedly.")
                dev.write(chunk)
                remaining -= len(chunk)
            dev.flush()
    except PermissionError:
        sys.exit(f"[restore-sd] permission denied on {args.sd_device}.")

    print("[restore-sd] write finished — verifying...")
    with open(args.sd_device, "rb") as dev:
        check = dev.read(total_bytes)
    if hashlib.sha256(check).hexdigest() == sha256_of(src):
        print("[restore-sd] VERIFIED successfully.")
    else:
        sys.exit("[restore-sd] MISMATCH — card contents do not match backup.")


# CLI Namespace Proxy container (`cli` object)
class CLIModule:
    pass

cli = CLIModule()
cli.DEFAULT_GDB = DEFAULT_GDB
cli.DEFAULT_OBJCOPY = DEFAULT_OBJCOPY
cli.DEFAULT_FLASH_ADDR = DEFAULT_FLASH_ADDR
cli.DEFAULT_FLASH_SIZE = DEFAULT_FLASH_SIZE
cli.SD_SECTOR_SIZE = SD_SECTOR_SIZE
cli.DEFAULT_SD_SECTOR_COUNT = DEFAULT_SD_SECTOR_COUNT
cli.DEFAULT_FLASH_FILE = DEFAULT_FLASH_FILE
cli.DEFAULT_SD_FILE = DEFAULT_SD_FILE
cli.SCRIPT_DIR = SCRIPT_DIR
cli.sha256_of = sha256_of
cli.resolve_tool = resolve_tool
cli.backup_flash = backup_flash
cli.make_flash_elf = make_flash_elf
cli.restore_flash = restore_flash
cli.backup_sd = backup_sd
cli.restore_sd = restore_sd


# ===========================================================================
# 2. UI Class (adapted from flipper_defucker.py[cite: 1])
# ===========================================================================

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(777, 782)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(100, 530, 141, 61))
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(540, 530, 141, 61))
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setGeometry(QtCore.QRect(320, 530, 151, 61))
        self.pushButton_3.setObjectName("pushButton_3")
        self.pushButton_4 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_4.setGeometry(QtCore.QRect(320, 640, 151, 61))
        self.pushButton_4.setObjectName("pushButton_4")
        self.pushButton_5 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_5.setGeometry(QtCore.QRect(540, 640, 141, 61))
        self.pushButton_5.setObjectName("pushButton_5")
        self.pushButton_6 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_6.setGeometry(QtCore.QRect(100, 640, 141, 61))
        self.pushButton_6.setObjectName("pushButton_6")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(120, 80, 531, 121))
        font = QtGui.QFont()
        font.setPointSize(50)
        self.label.setFont(font)
        self.label.setWordWrap(True)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(610, 150, 161, 81))
        font = QtGui.QFont()
        font.setPointSize(13)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.line = QtWidgets.QFrame(self.centralwidget)
        self.line.setGeometry(QtCore.QRect(40, 510, 41, 201))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.line.setFont(font)
        self.line.setLineWidth(5)
        self.line.setFrameShape(QtWidgets.QFrame.VLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.line_2 = QtWidgets.QFrame(self.centralwidget)
        self.line_2.setGeometry(QtCore.QRect(690, 510, 41, 201))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.line_2.setFont(font)
        self.line_2.setLineWidth(5)
        self.line_2.setFrameShape(QtWidgets.QFrame.VLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.line_3 = QtWidgets.QFrame(self.centralwidget)
        self.line_3.setGeometry(QtCore.QRect(490, 510, 41, 201))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.line_3.setFont(font)
        self.line_3.setLineWidth(5)
        self.line_3.setFrameShape(QtWidgets.QFrame.VLine)
        self.line_3.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_3.setObjectName("line_3")
        self.line_4 = QtWidgets.QFrame(self.centralwidget)
        self.line_4.setGeometry(QtCore.QRect(260, 510, 41, 201))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.line_4.setFont(font)
        self.line_4.setLineWidth(5)
        self.line_4.setFrameShape(QtWidgets.QFrame.VLine)
        self.line_4.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_4.setObjectName("line_4")
        self.line_5 = QtWidgets.QFrame(self.centralwidget)
        self.line_5.setGeometry(QtCore.QRect(60, 600, 651, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.line_5.setFont(font)
        self.line_5.setLineWidth(5)
        self.line_5.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_5.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_5.setObjectName("line_5")
        self.listWidget = QtWidgets.QListWidget(self.centralwidget)
        self.listWidget.setGeometry(QtCore.QRect(60, 280, 256, 151))
        self.listWidget.setObjectName("listWidget")
        self.listWidget_2 = QtWidgets.QListWidget(self.centralwidget)
        self.listWidget_2.setGeometry(QtCore.QRect(470, 280, 256, 151))
        self.listWidget_2.setObjectName("listWidget_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(320, 320, 151, 41))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(330, 350, 151, 41))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setGeometry(QtCore.QRect(30, 10, 761, 51))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setUnderline(True)
        font.setWeight(75)
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 777, 21))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Flipper De-Fucker"))
        self.pushButton.setText(_translate("MainWindow", "Dump Flash backup"))
        self.pushButton_2.setText(_translate("MainWindow", "Dump SD Card"))
        self.pushButton_3.setText(_translate("MainWindow", "Dump all"))
        self.pushButton_4.setText(_translate("MainWindow", "Write all"))
        self.pushButton_5.setText(_translate("MainWindow", "Write SD Card"))
        self.pushButton_6.setText(_translate("MainWindow", "Write Flash backup"))
        self.label.setText(_translate("MainWindow", "Flipper De-Fucker"))
        self.label_2.setText(_translate("MainWindow", "No, actually. It works"))
        self.label_3.setText(_translate("MainWindow", "<-- USB Port for BMP"))
        self.label_4.setText(_translate("MainWindow", "SD Card device -->"))
        self.label_5.setText(
            _translate(
                "MainWindow",
                "!!! THIS WILL BREAK YOUR HARDWARE AND/OR BACKUPS. YOU HAVE BEEN WARNED !!!",
            )
        )


# ===========================================================================
# 3. GUI Glue & Main Application (adapted from Flipper De-Fucker.py[cite: 3])
# ===========================================================================

@dataclass
class Device:
    label: str
    path: str
    blocked: str = ""
    preferred: bool = False


def fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1000:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def list_serial_ports() -> list[Device]:
    devices = []
    for info in QSerialPortInfo.availablePorts():
        desc = info.description() or info.manufacturer() or "serial port"
        ids = (
            f"  [{info.vendorIdentifier():04x}:{info.productIdentifier():04x}]"
            if info.hasVendorIdentifier() and info.hasProductIdentifier()
            else ""
        )
        devices.append(
            Device(
                f"{info.portName()} - {desc}{ids}",
                info.systemLocation(),
                preferred="gdb" in desc.lower(),
            )
        )
    return sorted(devices, key=lambda d: (len(d.path), d.path))


_PS_DISKS = (
    "try{[Console]::OutputEncoding=[Text.Encoding]::UTF8}catch{};"
    "Get-Disk | Select-Object Number,FriendlyName,Size,"
    "@{n='Bus';e={[string]$_.BusType}},IsBoot,IsSystem | ConvertTo-Json -Compress"
)


def parse_windows_disks(text: str) -> list[Device]:
    text = text.strip()
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):
        data = [data]
    devices = []
    for d in data:
        size = int(d.get("Size") or 0)
        if size == 0:
            continue
        number = d["Number"]
        name = (d.get("FriendlyName") or "unknown").strip()
        blocked = "system/boot disk" if d.get("IsSystem") or d.get("IsBoot") else ""
        label = f"PhysicalDrive{number} - {name} ({d.get('Bus') or '?'}, {fmt_size(size)})"
        if blocked:
            label += f"  [blocked: {blocked}]"
        devices.append(Device(label, rf"\\.\PhysicalDrive{number}", blocked))
    return devices


def parse_lsblk(text: str) -> list[Device]:
    def mounts(node):
        found = [node["mountpoint"]] if node.get("mountpoint") else []
        for child in node.get("children") or []:
            found += mounts(child)
        return found

    devices = []
    for d in json.loads(text).get("blockdevices", []):
        if d.get("type") != "disk" or d["name"].startswith(("loop", "ram", "zram", "nbd")):
            continue
        size = int(d.get("size") or 0)
        if size == 0:
            continue
        mp = mounts(d)
        blocked = (
            "holds the running system"
            if any(m == "/" or m.startswith("/boot") or m == "[SWAP]" for m in mp)
            else ""
        )
        path = d.get("path") or "/dev/" + d["name"]
        bus = (d.get("tran") or "").upper()
        label = f"{path} - {(d.get('model') or 'unknown').strip()} ({bus + ', ' if bus else ''}{fmt_size(size)})"
        if blocked:
            label += f"  [blocked: {blocked}]"
        elif mp:
            label += f"  [mounted: {', '.join(mp)}]"
        devices.append(Device(label, path, blocked))
    return devices


def list_sd_devices() -> list[Device]:
    if WINDOWS:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_DISKS],
            capture_output=True, text=True, encoding="utf-8-sig", errors="replace",
            timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if r.returncode:
            raise RuntimeError((r.stderr or "Get-Disk failed").strip())
        return parse_windows_disks(r.stdout)
    if platform.system() == "Linux":
        r = subprocess.run(
            ["lsblk", "-J", "-b", "-o", "NAME,PATH,SIZE,MODEL,TRAN,TYPE,MOUNTPOINT"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode:
            raise RuntimeError((r.stderr or "lsblk failed").strip())
        return parse_lsblk(r.stdout)
    return []


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True


class _SignalStream(io.TextIOBase):
    def __init__(self, signal):
        self._signal = signal

    def writable(self):
        return True

    def write(self, text):
        if text:
            self._signal.emit(text)
        return len(text)


class Task(QtCore.QThread):
    log = QtCore.pyqtSignal(str)
    done = QtCore.pyqtSignal(bool, object)

    def __init__(self, fn, workdir=None):
        super().__init__()
        self.fn, self.workdir = fn, workdir

    def run(self):
        out = _SignalStream(self.log)
        cwd = contextlib.chdir(self.workdir) if self.workdir else contextlib.nullcontext()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out), cwd:
                result = self.fn()
        except SystemExit as exc:
            ok = exc.code in (None, 0)
            self.done.emit(ok, None if ok else str(exc.code))
        except Exception as exc:
            self.done.emit(False, f"{type(exc).__name__}: {exc}")
        else:
            self.done.emit(True, result)


def _replace_atomically(final: str, produce):
    final = Path(final)
    part = final.with_name(final.name + ".part")
    part.unlink(missing_ok=True)
    try:
        produce(str(part))
        os.replace(part, final)
        print(f"[gui] saved {final.resolve()}")
    finally:
        part.unlink(missing_ok=True)


def step_dump_flash(ns):
    def produce(part):
        ns.flash_out = part
        cli.backup_flash(ns)
    _replace_atomically(cli.DEFAULT_FLASH_FILE, produce)


def step_dump_sd(ns):
    def produce(part):
        ns.sd_out = part
        cli.backup_sd(ns)
    _replace_atomically(cli.DEFAULT_SD_FILE, produce)


def step_write_flash(ns):
    src = Path(ns.flash_in)
    src.with_name(src.stem + ".verify.bin").unlink(missing_ok=True)
    cli.restore_flash(ns)


def step_write_sd(ns):
    cli.restore_sd(ns)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.cfg = QtCore.QSettings("FlipperDeFucker", "FlipperDeFucker")
        self.task = None
        self._scanned_sd, self._custom_sd = [], []

        self.port_list = self.ui.listWidget
        self.sd_list = self.ui.listWidget_2
        self.ui.pushButton.clicked.connect(self.dump_flash)
        self.ui.pushButton_2.clicked.connect(self.dump_sd)
        self.ui.pushButton_3.clicked.connect(self.dump_all)
        self.ui.pushButton_6.clicked.connect(self.write_flash)
        self.ui.pushButton_5.clicked.connect(self.write_sd)
        self.ui.pushButton_4.clicked.connect(self.write_all)

        self._build_log()
        self._build_menus()
        self.folder_label = QtWidgets.QLabel()
        self.statusBar().addPermanentWidget(self.folder_label)
        self._show_folder()

        self.say(f"Backup folder: {self.backup_dir}")
        if WINDOWS and not is_admin():
            self.say(
                "NOTE: not running as Administrator - SD card (raw disk) access will be refused. "
                "Flash operations are unaffected."
            )
        self.refresh_devices()

    @property
    def backup_dir(self) -> Path:
        return Path(self.cfg.value("backup_dir", str(cli.SCRIPT_DIR)))

    def _int(self, key, default):
        return self.cfg.value(key, default, type=int)

    def _show_folder(self):
        self.folder_label.setText(f"Backups: {self.backup_dir}")

    def _build_log(self):
        self.log = QtWidgets.QPlainTextEdit(readOnly=True)
        self.log.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont))
        self.log.setMinimumWidth(420)
        self.logdock = QtWidgets.QDockWidget("Log", self)
        self.logdock.setWidget(self.log)
        self.addDockWidget(Qt.RightDockWidgetArea, self.logdock)
        self.resize(self.width() + 430, self.height())

    def _append(self, text):
        self.log.moveCursor(QtGui.QTextCursor.End)
        self.log.insertPlainText(text)
        self.log.moveCursor(QtGui.QTextCursor.End)

    def say(self, text):
        self._append(text + "\n")

    def _build_menus(self):
        bar = self.menuBar()
        devices = bar.addMenu("&Devices")
        devices.addAction("&Refresh", self.refresh_devices, QtGui.QKeySequence("F5"))
        devices.addAction("Add SD device &path...", self.add_custom_sd)
        options = bar.addMenu("&Options")
        options.addAction("&Backup folder...", self.choose_backup_dir)
        options.addAction("&GDB executable...", lambda: self.choose_tool("gdb", "arm-none-eabi-gdb"))
        options.addAction("&objcopy executable...", lambda: self.choose_tool("objcopy", "arm-none-eabi-objcopy"))
        options.addSeparator()
        options.addAction("&Attach index...", self.set_attach_index)
        options.addAction("&Flash dump size...", self.set_flash_size)
        options.addAction("&SD sector count...", self.set_sd_sectors)
        view = bar.addMenu("&View")
        toggle = self.logdock.toggleViewAction()
        toggle.setText("Show &log")
        view.addAction(toggle)

    def choose_backup_dir(self):
        d = QtWidgets.QFileDialog.getExistingDirectory(self, "Backup folder", str(self.backup_dir))
        if d:
            self.cfg.setValue("backup_dir", d)
            self._show_folder()
            self.say(f"Backup folder: {d}")

    def choose_tool(self, key, name):
        text, ok = QtWidgets.QInputDialog.getText(
            self, name, f"Path to {name} (blank = automatic):",
            text=self.cfg.value(key, "", type=str),
        )
        if ok:
            self.cfg.setValue(key, text.strip())

    def set_attach_index(self):
        n, ok = QtWidgets.QInputDialog.getInt(
            self, "Attach index", "Target number from `monitor swdp_scan` (CM4 app core):",
            self._int("attach_index", 1), 1, 16,
        )
        if ok:
            self.cfg.setValue("attach_index", n)

    def set_flash_size(self):
        text, ok = QtWidgets.QInputDialog.getText(
            self, "Flash dump size", "Bytes to dump from 0x08000000 (hex or decimal):",
            text=hex(self._int("flash_size", cli.DEFAULT_FLASH_SIZE)),
        )
        if ok:
            try:
                size = int(text, 0)
                if size <= 0:
                    raise ValueError
            except ValueError:
                QMessageBox.warning(self, "Flash dump size", f"'{text}' isn't a positive number.")
                return
            self.cfg.setValue("flash_size", size)

    def set_sd_sectors(self):
        n, ok = QtWidgets.QInputDialog.getInt(
            self, "SD sector count", f"Sectors to read from LBA 0 ({cli.SD_SECTOR_SIZE} bytes each):",
            self._int("sd_sectors", cli.DEFAULT_SD_SECTOR_COUNT), 1, 1 << 24,
        )
        if ok:
            self.cfg.setValue("sd_sectors", n)

    def refresh_devices(self):
        if self.task:
            return
        self._fill(self.port_list, list_serial_ports())
        self._start(Task(list_sd_devices), self._scan_done, "Scanning drives...")

    def _scan_done(self, ok, result):
        self._end()
        if ok:
            self._scanned_sd = result
        else:
            self._scanned_sd = []
            self.say(f"Couldn't list drives: {result}\n(Devices > Add SD device path... still works.)")
        self._fill(self.sd_list, self._scanned_sd + self._custom_sd)
        self.say(f"Found {self.port_list.count()} serial port(s) and {self.sd_list.count()} drive(s).")

    def add_custom_sd(self):
        text, ok = QtWidgets.QInputDialog.getText(
            self, "Add SD device", "Raw device path (e.g. \\\\.\\PhysicalDrive3, /dev/sdb):",
        )
        if ok and text.strip():
            self._custom_sd.append(Device(f"{text.strip()}  (added by hand)", text.strip()))
            self._fill(self.sd_list, self._scanned_sd + self._custom_sd)
            self.sd_list.setCurrentRow(self.sd_list.count() - 1)

    def _fill(self, widget, devices):
        prev = widget.currentItem().data(Qt.UserRole).path if widget.currentItem() else None
        widget.clear()
        chosen = None
        for dev in devices:
            item = QtWidgets.QListWidgetItem(dev.label)
            item.setData(Qt.UserRole, dev)
            if dev.blocked:
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled & ~Qt.ItemIsSelectable)
                item.setToolTip(f"Not selectable: {dev.blocked}")
            widget.addItem(item)
            if not dev.blocked and (dev.path == prev or (prev is None and chosen is None and dev.preferred)):
                chosen = item
        if chosen:
            widget.setCurrentItem(chosen)

    def _pick(self, widget, what):
        item = widget.currentItem()
        if item is None:
            QMessageBox.warning(self, "Nothing selected", f"Select {what} first.")
            return None
        return item.data(Qt.UserRole)

    def _pick_port(self):
        return self._pick(self.port_list, "the Black Magic Probe's GDB port (left list)")

    def _pick_disk(self):
        return self._pick(self.sd_list, "the SD card (right list)")

    def dump_flash(self):
        port = self._pick_port()
        if port and self._ok_to_replace([cli.DEFAULT_FLASH_FILE]):
            self._execute("Dump flash", [step_dump_flash], port=port)

    def dump_sd(self):
        disk = self._pick_disk()
        if disk and not self._admin_missing() and self._ok_to_replace([cli.DEFAULT_SD_FILE]):
            self._execute("Dump SD card", [step_dump_sd], disk=disk)

    def dump_all(self):
        port = self._pick_port()
        disk = self._pick_disk() if port else None
        if port and disk and not self._admin_missing() and self._ok_to_replace([cli.DEFAULT_FLASH_FILE, cli.DEFAULT_SD_FILE]):
            self._execute("Dump all", [step_dump_flash, step_dump_sd], port=port, disk=disk)

    def write_flash(self):
        port = self._pick_port()
        if port and self._ready_to_write(port=port):
            self._execute("Write flash backup", [step_write_flash], port=port)

    def write_sd(self):
        disk = self._pick_disk()
        if disk and not self._admin_missing() and self._ready_to_write(disk=disk):
            self._execute("Write SD card", [step_write_sd], disk=disk)

    def write_all(self):
        port = self._pick_port()
        disk = self._pick_disk() if port else None
        if port and disk and not self._admin_missing() and self._ready_to_write(port=port, disk=disk):
            self._execute("Write all", [step_write_flash, step_write_sd], port=port, disk=disk)

    def _confirm(self, title, text, ok_label) -> bool:
        box = QMessageBox(QMessageBox.Warning, title, text, QMessageBox.NoButton, self)
        ok = box.addButton(ok_label, QMessageBox.AcceptRole)
        cancel = box.addButton(QMessageBox.Cancel)
        box.setDefaultButton(cancel)
        box.exec_()
        return box.clickedButton() is ok

    def _admin_missing(self) -> bool:
        if WINDOWS and not is_admin():
            QMessageBox.warning(
                self, "Administrator required",
                "Raw access to \\\\.\\PhysicalDriveN needs an elevated process.\n"
                "Restart this app from an Administrator terminal.",
            )
            return True
        return False

    def _ok_to_replace(self, names) -> bool:
        existing = [self.backup_dir / n for n in names if (self.backup_dir / n).exists()]
        if not existing:
            return True
        lines = "\n".join(
            f"  {p.name} - {p.stat().st_size:,} bytes, {time.strftime('%Y-%m-%d %H:%M', time.localtime(p.stat().st_mtime))}"
            for p in existing
        )
        return self._confirm(
            "Replace existing backup?",
            f"This will replace:\n\n{lines}\n\nIf the device has already been wiped, "
            "the old file may be your only good copy.",
            "Replace",
        )

    def _ready_to_write(self, port=None, disk=None) -> bool:
        parts = []
        if port:
            f = self.backup_dir / cli.DEFAULT_FLASH_FILE
            if not self._have(f):
                return False
            parts.append(
                f"FLASH  <-  {f.name}  ({f.stat().st_size:,} bytes, sha256 {cli.sha256_of(f)[:16]}...)\n"
                f"into {cli.DEFAULT_FLASH_ADDR:#010x} via {port.path}, "
                f"attach index {self._int('attach_index', 1)}"
            )
        if disk:
            f = self.backup_dir / cli.DEFAULT_SD_FILE
            if not self._have(f):
                return False
            n = f.stat().st_size
            parts.append(
                f"SD CARD  <-  {f.name}  ({n:,} bytes = LBA 0-{n // cli.SD_SECTOR_SIZE - 1})\n"
                f"onto {disk.label}"
            )
        return self._confirm(
            "Write to hardware?",
            "\n\n".join(parts) + "\n\nThis overwrites what is there now.",
            "Write",
        )

    def _have(self, path: Path) -> bool:
        if path.exists():
            return True
        QMessageBox.warning(
            self, "Backup not found",
            f"{path.name} isn't in {path.parent}.\nDump first, or point Options > Backup folder "
            "at the right place.",
        )
        return False

    def _namespace(self, port, disk) -> argparse.Namespace:
        return argparse.Namespace(
            port=port.path if port else None,
            gdb=self.cfg.value("gdb", "", type=str) or None,
            objcopy=self.cfg.value("objcopy", "", type=str) or None,
            attach_index=self._int("attach_index", 1),
            flash_addr=cli.DEFAULT_FLASH_ADDR,
            flash_size=self._int("flash_size", cli.DEFAULT_FLASH_SIZE),
            flash_out=cli.DEFAULT_FLASH_FILE,
            flash_in=cli.DEFAULT_FLASH_FILE,
            sd_device=disk.path if disk else None,
            sd_sector_count=self._int("sd_sectors", cli.DEFAULT_SD_SECTOR_COUNT),
            sd_out=cli.DEFAULT_SD_FILE,
            sd_in=cli.DEFAULT_SD_FILE,
        )

    def _execute(self, title, steps, port=None, disk=None):
        ns = self._namespace(port, disk)

        def job():
            for step in steps:
                step(ns)

        self.say(f"\n=== {title} ===")
        self._start(
            Task(job, workdir=str(self.backup_dir)),
            lambda ok, res: self._op_done(title, ok, res),
            f"{title}...",
        )

    def _op_done(self, title, ok, result):
        self._end()
        if ok:
            self.say(f"=== {title}: OK ===")
            QMessageBox.information(self, title, "Finished OK - details are in the log.")
        else:
            self.say(f"=== {title}: FAILED ===\n{result}")
            QMessageBox.critical(self, f"{title} failed", str(result))

    def _start(self, task, on_done, status):
        self.task = task
        task.log.connect(self._append)
        task.done.connect(on_done)
        self.ui.centralwidget.setEnabled(False)
        self.menuBar().setEnabled(False)
        QtWidgets.QApplication.setOverrideCursor(Qt.BusyCursor)
        self.statusBar().showMessage(status)
        task.start()

    def _end(self):
        self.task.wait()
        self.task = None
        QtWidgets.QApplication.restoreOverrideCursor()
        self.statusBar().clearMessage()
        self.ui.centralwidget.setEnabled(True)
        self.menuBar().setEnabled(True)

    def closeEvent(self, event):
        if self.task:
            QMessageBox.warning(
                self, "Busy",
                "An operation is still running - closing now could leave the "
                "device half-written. Wait for it to finish.",
            )
            event.ignore()
        else:
            event.accept()


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()