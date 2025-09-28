#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
logcat.py — Android Logcat Parser
Скрипт для чтения логов Android через ADB или из файла, их фильтрации
и экспорта в удобные форматы (TTY, JSON, CSV).
"""

import argparse
import subprocess
import sys
import re
import json
import csv
import os
import time
import datetime
from typing import Dict, Generator, Optional

# Попробуем подключить colorama для кроссплатформенных цветов
try:
    from colorama import init, Fore, Style
    init()
    COLORAMA = True
except ImportError:
    COLORAMA = False


# ----------- Парсинг строк логов -----------

# Регексы для разных форматов
REGEX_THREADTIME = re.compile(
    r"^(?P<date>\d\d-\d\d)\s+(?P<time>\d\d:\d\d:\d\d\.\d+)\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEF])\s+(?P<tag>[^:]+):\s+(?P<msg>.*)$"
)

REGEX_TIME = re.compile(
    r"^(?P<date>\d\d-\d\d)\s+(?P<time>\d\d:\d\d:\d\d\.\d+)\s+"
    r"(?P<level>[VDIWEF])\s+(?P<tag>[^:]+):\s+(?P<msg>.*)$"
)

REGEX_EPOCH = re.compile(
    r"^(?P<epoch>\d+\.\d+)\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s+"
    r"(?P<level>[VDIWEF])\s+(?P<tag>[^:]+):\s+(?P<msg>.*)$"
)


def detect_format(line: str) -> str:
    """Определяем формат лога по строке"""
    if REGEX_THREADTIME.match(line):
        return "threadtime"
    elif REGEX_TIME.match(line):
        return "time"
    elif REGEX_EPOCH.match(line):
        return "epoch"
    return "unknown"


def parse_line(line: str, fmt: str) -> Optional[Dict]:
    """Парсим строку лога в словарь"""
    m = None
    if fmt == "threadtime":
        m = REGEX_THREADTIME.match(line)
    elif fmt == "time":
        m = REGEX_TIME.match(line)
    elif fmt == "epoch":
        m = REGEX_EPOCH.match(line)

    if not m:
        return None

    gd = m.groupdict()

    # timestamp → datetime
    if fmt == "epoch":
        ts = datetime.datetime.utcfromtimestamp(float(gd["epoch"]))
    else:
        year = datetime.datetime.now().year
        dt_str = f"{year}-{gd['date']} {gd['time']}"
        ts = datetime.datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")

    rec = {
        "ts_raw": gd.get("epoch") or f"{gd['date']} {gd['time']}",
        "ts_iso": ts.isoformat(),
        "pid": int(gd["pid"]) if gd.get("pid") else None,
        "tid": int(gd["tid"]) if gd.get("tid") else None,
        "level": gd["level"],
        "tag": gd["tag"].strip(),
        "msg": gd["msg"],
    }
    return rec


# ----------- Фильтры -----------

def make_filters(args):
    """Создаем список фильтров на основе аргументов"""
    filters = []

    if args.min_level:
        levels = "VDIWEF"
        min_idx = levels.index(args.min_level)
        filters.append(lambda r: levels.index(r["level"]) >= min_idx)

    if args.tag:
        allowed_tags = set(args.tag)
        filters.append(lambda r: r["tag"] in allowed_tags)

    if args.grep:
        regex = re.compile(args.grep, re.I if args.ignore_case else 0)
        filters.append(lambda r: regex.search(r["msg"]) is not None)

    if args.contains:
        substr = args.contains.lower() if args.ignore_case else args.contains
        filters.append(
            lambda r: substr in (r["msg"].lower() if args.ignore_case else r["msg"])
        )

    if args.pid:
        filters.append(lambda r: r["pid"] == args.pid)

    def apply_all(rec):
        return all(f(rec) for f in filters)

    return apply_all


# ----------- Источники -----------

def iter_adb_lines(args) -> Generator[str, None, None]:
    """Читаем строки из ADB"""
    adb = args.adb_path or "adb"
    cmd = [adb]
    if args.serial:
        cmd += ["-s", args.serial]
    cmd += ["logcat", "-v", args.format]

    if args.buffer != "main":
        cmd += ["-b", args.buffer]

    if args.clear:
        subprocess.run(cmd + ["-c"])

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in proc.stdout:
        yield line.rstrip("\n")


def iter_file_lines(path: str, follow=False) -> Generator[str, None, None]:
    """Читаем строки из файла"""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        while True:
            line = f.readline()
            if not line:
                if follow:
                    time.sleep(0.2)
                    continue
                break
            yield line.rstrip("\n")


# ----------- Writers -----------

class TTYWriter:
    """Человекочитаемый вывод"""

    COLORS = {
        "V": Style.DIM if COLORAMA else "",
        "D": "",
        "I": Fore.GREEN if COLORAMA else "",
        "W": Fore.YELLOW if COLORAMA else "",
        "E": Fore.RED if COLORAMA else "",
        "F": Fore.RED + Style.BRIGHT if COLORAMA else "",
    }

    def __init__(self, args):
        self.args = args

    def write(self, rec):
        ts = rec["ts_iso"].split("T")[1]
        pid = rec["pid"] or "-"
        tid = rec["tid"] or "-"
        lvl = rec["level"]
        color = self.COLORS.get(lvl, "")
        reset = Style.RESET_ALL if COLORAMA else ""
        msg = rec["msg"]

        if self.args.no_color:
            color = reset = ""

        print(f"{ts} {pid}/{tid} {color}{lvl}{reset} {rec['tag']}: {msg}")

    def close(self):
        pass


class JSONWriter:
    def __init__(self, path, indent=None):
        self.f = open(path, "w", encoding="utf-8")
        self.indent = indent

    def write(self, rec):
        json.dump(rec, self.f, ensure_ascii=False, indent=self.indent)
        self.f.write("\n")

    def close(self):
        self.f.close()


class CSVWriter:
    def __init__(self, path):
        self.f = open(path, "w", newline="", encoding="utf-8")
        self.w = None

    def write(self, rec):
        if not self.w:
            self.w = csv.DictWriter(self.f, fieldnames=list(rec.keys()))
            self.w.writeheader()
        self.w.writerow(rec)

    def close(self):
        self.f.close()


# ----------- Main -----------

def main():
    p = argparse.ArgumentParser(description="Android Logcat Parser")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--adb", action="store_true", help="Читать из ADB")
    src.add_argument("--input", help="Читать из файла")

    p.add_argument("--serial", help="ADB serial")
    p.add_argument("--adb-path", help="Путь к adb")
    p.add_argument("--buffer", default="main", help="Буфер (main, system, events, radio, crash, all)")
    p.add_argument("--format", default="threadtime", help="Формат вывода adb (time, threadtime, epoch)")
    p.add_argument("--clear", action="store_true", help="Очистить буфер перед стартом")

    # Фильтры
    p.add_argument("--min-level", choices=list("VDIWEF"))
    p.add_argument("--tag", nargs="+", help="Фильтр по тегам")
    p.add_argument("--grep", help="Регекс по сообщению")
    p.add_argument("--contains", help="Подстрока в сообщении")
    p.add_argument("-i", "--ignore-case", action="store_true")
    p.add_argument("--pid", type=int)

    # Вывод
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--json", help="Сохранить в JSON")
    p.add_argument("--csv", help="Сохранить в CSV")
    p.add_argument("--json-indent", type=int)

    args = p.parse_args()

    # Источник
    if args.adb:
        src = iter_adb_lines(args)
    else:
        src = iter_file_lines(args.input)

    # Определяем формат (для файлов auto)
    fmt = args.format
    if not args.adb and args.format == "auto":
        for l in src:
            fmt = detect_format(l)
            if fmt != "unknown":
                first_line = l
                break
        else:
            print("Не удалось определить формат", file=sys.stderr)
            return
        src = [first_line] + list(iter_file_lines(args.input))

    # Фильтры
    flt = make_filters(args)

    # Writers
    writers = []
    if args.json:
        writers.append(JSONWriter(args.json, indent=args.json_indent))
    if args.csv:
        writers.append(CSVWriter(args.csv))
    if not writers:
        writers.append(TTYWriter(args))

    try:
        for line in src:
            rec = parse_line(line, fmt)
            if not rec:
                continue
            if not flt(rec):
                continue
            for w in writers:
                w.write(rec)
    except KeyboardInterrupt:
        pass
    finally:
        for w in writers:
            w.close()


if __name__ == "__main__":
    main()