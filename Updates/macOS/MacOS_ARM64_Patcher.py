#!/usr/bin/env python3
# ARM64-only patches for discord_voice.node on Apple Silicon (GUI + CLI).

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import hashlib
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Protocol, Tuple

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
except Exception:
    tk = None  # type: ignore


class LogSink(Protocol):
    def info(self, msg: str) -> None: ...
    def ok(self, msg: str) -> None: ...
    def warn(self, msg: str) -> None: ...
    def fail(self, msg: str) -> None: ...


APP_NAME = "Discord Stereo Patcher"
APP_VERSION = "1.0.0"

TARGET_BITRATE_BPS = 248000
_BITRATE_LITERAL_ORIG = bytes.fromhex("00 7D 00 00")
_BITRATE_LITERAL_PATCH = TARGET_BITRATE_BPS.to_bytes(4, "little")

# MOVZ Wd, #0x7D00 (32000) — base opcode + mask over the Rd field (bits 4:0).
_BITRATE_MOVZ_W_MASK = 0xFFFFFFE0   # MOVZ Wd, #32000 with any Rd
_BITRATE_MOVZ_W_BASE = 0x528FA000   # MOVZ W?, #0x7D00 (32000)


def _arm64_cbz(rt: int, target_insn: int, from_insn: int) -> int:
    """Encode CBZ (32-bit). ARM A64 defines target = PC_branch + (imm19 << 2),
    so imm19 = target_idx - branch_idx (NOT target - (from + 1))."""
    imm19 = target_insn - from_insn
    if not (-(1 << 18) <= imm19 < (1 << 18)):
        raise ValueError(f"CBZ imm19 out of range: {imm19}")
    return 0x34000000 | ((imm19 & 0x7FFFF) << 5) | (rt & 0x1F)


def _arm64_b_ne(target_insn: int, from_insn: int) -> int:
    """Encode B.NE with imm19 = target - from."""
    imm19 = target_insn - from_insn
    if not (-(1 << 18) <= imm19 < (1 << 18)):
        raise ValueError(f"B.NE imm19 out of range: {imm19}")
    return 0x54000001 | ((imm19 & 0x7FFFF) << 5)


def _arm64_ldr_si_post(rt: int, rn: int, imm9: int) -> int:
    """LDR St, [Xn], #imm9 (post-index, 32-bit SIMD)."""
    return 0xBC400000 | ((imm9 & 0x1FF) << 12) | (1 << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)


def _arm64_str_si_post(rt: int, rn: int, imm9: int) -> int:
    """STR St, [Xn], #imm9 (post-index, 32-bit SIMD)."""
    return 0xBC000000 | ((imm9 & 0x1FF) << 12) | (1 << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)


def _arm64_subs_imm32(rd: int, rn: int, imm12: int) -> int:
    """SUBS Wd, Wn, #imm12 (32-bit, no shift)."""
    return 0x71000000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def _arm64_passthrough_shellcode(len_reg: int, ch_reg: int, out_reg: int) -> bytes:
    """Copy len*channels float samples in->out; filterless passthrough for hp_cutoff/dc_reject.

    Layout (8 instructions, 32 bytes):
        0: CBZ     W<len>, RET          ; early-exit if len == 0
        1: MUL     W11, W<len>, W<ch>   ; total = len * channels
        2: CBZ     W11, RET             ; early-exit if total == 0
        3: LDR     S4, [X0], #4         ; load input float, post-increment X0
        4: STR     S4, [X<out>], #4     ; store to output, post-increment X<out>
        5: SUBS    W11, W11, #1         ; --total, set flags
        6: B.NE    LOOP (insn 3)        ; loop while total != 0
        7: RET

    Used to generate the patch bytes for hp_cutoff and dc_reject above. Re-run if registers change.

    BUGFIX: the MUL encoding previously emitted `0x1B000000 | (Rm<<16) | (Rn<<5) | Rd`,
    which leaves the Ra field (bits 14-10) at 0 -> Ra = W0. Capstone therefore
    disassembled the result as `madd W11, W<len>, W<ch>, W0` (= W11 = W0 +
    W<len>*W<ch>) instead of `mul`. Because W0 holds the lower 32 bits of the
    input pointer (a large value), the loop counter became billions and the
    LDR/STR loop ran off the end of both buffers, crashing Discord the moment
    hp_cutoff or dc_reject was called. Setting Ra = 31 (WZR) yields the
    intended `mul` encoding.
    """
    loop_insn, ret_insn = 3, 7
    ins = [0] * 8
    ins[0] = _arm64_cbz(len_reg, ret_insn, 0)
    # MUL W11, W<len>, W<ch> == MADD W11, W<len>, W<ch>, WZR (Ra = 31 = 0x1F).
    _RA_WZR = 31
    ins[1] = (
        0x1B000000
        | ((ch_reg & 0x1F) << 16)
        | (_RA_WZR << 10)
        | ((len_reg & 0x1F) << 5)
        | 11
    )
    ins[2] = _arm64_cbz(11, ret_insn, 2)
    ins[3] = _arm64_ldr_si_post(rt=4, rn=0, imm9=4)
    ins[4] = _arm64_str_si_post(rt=4, rn=out_reg, imm9=4)
    ins[5] = _arm64_subs_imm32(rd=11, rn=11, imm12=1)
    ins[6] = _arm64_b_ne(loop_insn, 6)
    ins[7] = 0xD65F03C0  # RET
    return struct.pack("<8I", *ins)


# region ARM64 Patches (PASTE HERE) -> apply_arm64_stereo_patches.py
PATCHES_META = {
    "finder_version": "discord_voice_node_offset_finder_v5.py v5.11.0",
    "discord_app_version": "unspecified",
    "file_size": 51474192,
    # Verified SHA-256 of the stock discord_voice.node (matches the binary
    # published at Updates/Nodes/Unpatched Nodes (For Patcher)/macOS/).
    # Also retains the legacy MD5 under "md5" so older branches that still
    # read md5_file (= sha256_file alias) keep working.
    "sha256": "d1d0643a3c33561fa2b2a3486fc8b2c45db57777b21a6b22cc383d6e98127f8d",
    "md5": "c3efcdd6b6b11698eca006a9d93d7de5",
    "arm64_slice_offset": 0x1A80000,
    "arm64_slice_size": 23686928,
}

ARM64_PATCHES: List[dict] = [
    # --- Stereo (channels + downmix bypass) ---
    {"name": "MultiChannelOpusConfig_channels", "fat_offset": 0x1DEDA90, "orig": "28", "patch": "48"},
    {"name": "OpusConfig_channels", "fat_offset": 0x1DEDED4, "orig": "28", "patch": "48"},
    {"name": "StereoDownmixChannels", "fat_offset": 0x1CD0F30, "orig": "F6 57 BD A9", "patch": "C0 03 5F D6"},
    {"name": "StereoDownMixFrame", "fat_offset": 0x1E3F06C, "orig": "20 01 00 34", "patch": "1F 20 03 D5"},
    {"name": "StereoApplyAudioNetworkAdaptor", "fat_offset": 0x1DF07A4, "orig": "41 01 00 54", "patch": "1F 20 03 D5"},
    {"name": "SdpToConfig_cinc1", "fat_offset": 0x1DEEE34, "orig": "15 15 88 9A", "patch": "55 00 80 52"},
    {"name": "SdpToConfig_mov1", "fat_offset": 0x1DEEE3C, "orig": "35", "patch": "55"},
    {"name": "SdpToConfig_cinc2", "fat_offset": 0x1DEEE5C, "orig": "15 15 88 9A", "patch": "55 00 80 52"},
    {"name": "SdpToConfig_mov2", "fat_offset": 0x1DEEE64, "orig": "35", "patch": "55"},
    {"name": "CommitAudioCodec_stereo_force", "fat_offset": 0x222A0B8, "orig": "1F 05 00 71", "patch": "1F 0A 00 71"},
    {"name": "CommitAudioCodec_stereo_force2", "fat_offset": 0x222A250, "orig": "E1 00 00 54", "patch": "06 00 00 14"},
    {"name": "OpusConfig_IsOk", "fat_offset": 0x1DEE048, "orig": "08 00 40 B9 A9 99 99 52", "patch": "20 00 80 52 C0 03 5F D6"},
    {"name": "MultiChannelOpusConfig_IsOk", "fat_offset": 0x1DEDC5C, "orig": "FF 03 01 D1 F4 4F 02 A9", "patch": "20 00 80 52 C0 03 5F D6"},
    {"name": "CreateAudioFrame_channels1", "fat_offset": 0x2220A98, "orig": "3B", "patch": "5B"},
    {"name": "CreateAudioFrame_channels2", "fat_offset": 0x2220AD0, "orig": "3B", "patch": "5B"},
    {"name": "InitializeHighPassFilter_bypass", "fat_offset": 0x1CB8D7C, "orig": "F6 57 BD A9", "patch": "C0 03 5F D6"},
    {"name": "NumProcChannels_force_stereo", "fat_offset": 0x1CB99D4, "orig": "08 B4 45 39 1F 05 00 71", "patch": "40 00 80 52 C0 03 5F D6"},
    {"name": "DownmixInterleavedToMono_bypass", "fat_offset": 0x1A9B62C, "orig": "48 7C 40 93", "patch": "C0 03 5F D6"},
    {"name": "NoiseCanceller_bypass", "fat_offset": 0x21DC034, "orig": "FF 03 02 D1", "patch": "C0 03 5F D6"},
    {"name": "CustomCapturePostproc_bypass", "fat_offset": 0x2201104, "orig": "AE 6C FF 17", "patch": "1F 20 03 D5"},
    {"name": "ProcessStream_bypass", "fat_offset": 0x1CBB71C, "orig": "E1 00 00 54", "patch": "1F 20 03 D5"},
    {"name": "CapturedAudioProcessor_MonoDownmix", "fat_offset": 0x21EE8B4, "orig": "48 02 00 37", "patch": "1F 20 03 D5"},
    {"name": "ChannelDownmix_Entry_Ret", "fat_offset": 0x1DD5838, "orig": "E9 23 B9 6D", "patch": "C0 03 5F D6"},
    {"name": "CodecMismatchThrow_Entry_Ret", "fat_offset": 0x214D560, "orig": "FF 43 01 D1", "patch": "C0 03 5F D6"},

    # --- 48 kHz sample rate ---
    {"name": "SelectSampleRate_Cmov48k_Nop3", "fat_offset": 0x222A528, "orig": "E2 17 9F 1A", "patch": "1F 20 03 D5"},
    {"name": "CommitAudioCodec_ChannelCount_alt", "fat_offset": 0x222A01C, "orig": "1F 05 00 71", "patch": "1F 0A 00 71"},

    # --- 10 ms frames + 248 kbps config defaults ---
    {"name": "OpusConfig_FrameMs_Rodata", "fat_offset": 0x24FDAC8, "orig": "14", "patch": "0A"},
    {"name": "OpusConfig_Bitrate_Rodata", "fat_offset": 0x24FDABC, "orig": "00 7D 00 00", "patch": "C0 C8 03 00"},
    {"name": "MultiChannel_FrameMs_Imm10", "fat_offset": 0x1DEDA88, "orig": "88 02 80 52", "patch": "08 01 80 52"},

    # --- Force CELT (opus_encoder_init) ---
    {"name": "CELT_Force", "fat_offset": 0x24FD4C0, "orig": "18 FC FF FF FF FF FF FF", "patch": "EA 03 00 00 00 00 00 00"},
    # BUGFIX: previous patch bytes were `40 7D 80 52` which decode as
    # `mov w0, #0x3ea` — Rd silently changed from w8 to w0, so the next
    # instruction `str w8, [x19, #0x3794]` stored the OLD w8 value (1001 =
    # OPUS_APPLICATION_VOIP) instead of the intended 1002 = AUDIO. The
    # correct encoding for `mov w8, #0x3ea` (preserving Rd=8) is
    # 0x52807D48 -> LE bytes `48 7D 80 52`.
    {"name": "CELT_DefaultMode", "fat_offset": 0x1DD9AB0, "orig": "28 7D 80 52", "patch": "48 7D 80 52"},

    # --- Filterless: hp_cutoff / dc_reject passthrough shellcode ---
    # BUGFIX: the second instruction of each shellcode was encoded as
    # `MADD W11, W<len>, W<ch>, W0` (= W11 = W0 + W<len>*W<ch>) instead of
    # `MUL W11, W<len>, W<ch>` (= W11 = W<len>*W<ch>). Because W0 holds the
    # lower 32 bits of the input pointer (a large value like 0x6F000000),
    # the loop counter W11 became ~1.8 billion, causing the LDR/STR loop to
    # overrun both buffers and crash Discord. Fixed by setting Ra=31 (WZR)
    # in the MADD encoding so capstone disassembles it as `mul`:
    #   hp_cutoff: 8B 00 05 1B  ->  8B 7C 05 1B
    #   dc_reject: 6B 00 04 1B  ->  6B 7C 04 1B
    {
        "name": "hp_cutoff_Callback_InjectShellcode",
        "fat_offset": 0x1DDD730,
        "orig": "9F 04 00 71 6B 09 00 54 09 00 80 D2 28 3C 00 13 EA 34 81 52 08 7D 0A 1B 6A BA 89 52 4A 0C A2 72",
        "patch": "E4 00 00 34 8B 7C 05 1B AB 00 00 34 04 44 40 BC 44 44 00 BC 6B 05 00 71 A1 FF FF 54 C0 03 5F D6",
    },
    {
        "name": "dc_reject_Callback_InjectShellcode",
        "fat_offset": 0x1DDD864,
        "orig": "A0 00 22 1E 88 66 86 52 E8 32 A8 72 01 01 27 1E 21 18 20 1E 00 10 2E 1E 02 38 21 1E 40 00 40 BD",
        "patch": "E3 00 00 34 6B 7C 04 1B AB 00 00 34 04 44 40 BC 24 44 00 BC 6B 05 00 71 A1 FF FF 54 C0 03 5F D6",
    },
]
# endregion ARM64 Patches

ARM64_STEREO_SPEC_NAMES = [p["name"] for p in ARM64_PATCHES]


def _hex_bytes(s: str) -> bytes:
    return bytes(int(b, 16) for b in s.split() if b)

def sha256_file(path: Path) -> str:
    """SHA-256 of a file (streams in 1 MB chunks)."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

# Backward-compat alias — older callers and tests may still reference md5_file.
# NOTE: this now returns a SHA-256 digest, not an MD5 digest.
md5_file = sha256_file


def _arm64_is_movz_w(raw: int, imm16: int) -> bool:
    return (raw & 0xFFFFFFE0) == (0x52800000 | (imm16 << 5))


def _arm64_movz_32000_to_248k_bytes(rd: int) -> bytes:
    movz = 0x52800000 | (rd & 0x1F) | (0xC850 << 5)
    movk = 0x72800000 | (rd & 0x1F) | (3 << 5) | (1 << 21)
    return struct.pack("<II", movz, movk)


def find_macos_stereo_patches(data: bytes) -> List[dict]:
    """Resolve static ARM64 patch sites against the fat binary.

    Emits an entry for every spec whose region is within the file. Each entry
    carries one of three states: original bytes (default), `already_patched=True`,
    or `mismatch=True` (bytes match neither `orig` nor `patch`).
    """
    if len(data) < 8:
        return []
    out: List[dict] = []
    for spec in ARM64_PATCHES:
        fo = spec["fat_offset"]
        orig = _hex_bytes(spec["orig"])
        patch_b = _hex_bytes(spec["patch"])
        if fo + max(len(orig), len(patch_b)) > len(data):
            continue
        current = data[fo : fo + len(orig)]
        entry = {
            "arch": "arm64",
            "name": spec["name"],
            "fat_offset": fo,
            "orig": spec["orig"],
            "patch": spec["patch"],
        }
        if current == orig:
            out.append(entry)
        elif data[fo : fo + len(patch_b)] == patch_b:
            entry["already_patched"] = True
            out.append(entry)
        else:
            # M2: surface the mismatch explicitly instead of silently dropping.
            entry["mismatch"] = True
            out.append(entry)
    return out


def missing_arm64_stereo_patch_names(data: bytes) -> List[str]:
    found = {p["name"] for p in find_macos_stereo_patches(data) if not p.get("mismatch")}
    return [n for n in ARM64_STEREO_SPEC_NAMES if n not in found]


def _scan_arm64_bitrate_literals(
    data: bytearray, touched_ranges: List[Tuple[int, int]]
) -> Tuple[int, List[str]]:
    """Replace the 4-byte literal 32000 (LE) with 248000 (LE) ONLY when preceded
    by a MOVZ Wd, #0x7D00 instruction (the actual bitrate-load idiom).

    Constrained to instruction-aligned sites within the ARM64 slice. Skips any
    range already touched by a static patch.
    """
    fo = PATCHES_META["arm64_slice_offset"]
    end = min(fo + PATCHES_META["arm64_slice_size"], len(data) - 8)
    applied = 0
    names: List[str] = []

    def _overlaps(start: int, length: int) -> bool:
        return any(not (start + length <= s or start >= s + l) for s, l in touched_ranges)

    # Align to 4 bytes (ARM64 instruction alignment).
    i = fo
    if i % 4:
        i += 4 - (i % 4)
    while i < end:
        if _overlaps(i, 8):
            i += 4
            continue
        raw = struct.unpack_from("<I", data, i)[0]
        if (raw & _BITRATE_MOVZ_W_MASK) == _BITRATE_MOVZ_W_BASE:
            # Check that the next 4 bytes are the literal 32000 (LE).
            if data[i + 4 : i + 8] == _BITRATE_LITERAL_ORIG:
                data[i + 4 : i + 8] = _BITRATE_LITERAL_PATCH
                touched_ranges.append((i + 4, 4))
                applied += 1
                names.append(f"bitrate_literal@0x{i + 4:X}")
        i += 4
    return applied, names


def _scan_arm64_movz_32000(
    data: bytearray, touched_ranges: List[Tuple[int, int]]
) -> Tuple[int, List[str]]:
    """Rewrite MOVZ Wd, #32000 + the trailing 4-byte literal into the 248 kbps
    pair. Writes 8 bytes per site — guarded by touched_ranges overlap check so
    we never re-patch inside a static patch site.
    """
    fo = PATCHES_META["arm64_slice_offset"]
    end = min(fo + PATCHES_META["arm64_slice_size"], len(data) - 7)
    applied = 0
    names: List[str] = []

    def _overlaps(start: int, length: int) -> bool:
        return any(not (start + length <= s or start >= s + l) for s, l in touched_ranges)

    for i in range(fo, end, 4):
        if _overlaps(i, 8):
            continue
        raw = struct.unpack_from("<I", data, i)[0]
        if not _arm64_is_movz_w(raw, 32000):
            continue
        patch = _arm64_movz_32000_to_248k_bytes(raw & 0x1F)
        data[i : i + len(patch)] = patch
        touched_ranges.append((i, len(patch)))
        applied += 1
        names.append(f"movz_32000@0x{i:X}")
    return applied, names


def apply_macos_stereo_patches(data, arm64_only: bool = False) -> Tuple[int, int, List[str]]:
    patches = find_macos_stereo_patches(data)
    if arm64_only:
        patches = [p for p in patches if p.get("arch") == "arm64"]
    if not patches:
        return 0, 0, []

    if not isinstance(data, bytearray):
        data = bytearray(data)

    seen: set = set()
    applied = skipped = 0
    names: List[str] = []
    for p in patches:
        fo = p["fat_offset"]
        orig = _hex_bytes(p["orig"])
        patch = _hex_bytes(p["patch"])
        key = (fo, orig.hex())
        if key in seen:
            continue
        seen.add(key)
        if fo + len(patch) > len(data):
            skipped += 1
            continue
        current = bytes(data[fo : fo + len(orig)])
        if current == orig:
            data[fo : fo + len(patch)] = patch
            applied += 1
            names.append(p["name"])
        elif current == patch or p.get("already_patched"):
            skipped += 1
            names.append(p["name"] + " (already)")
        else:
            # M2: surface mismatches explicitly instead of silently skipping.
            # Callers can count "(mismatch)" suffixes in `names` for telemetry.
            skipped += 1
            names.append(p["name"] + " (mismatch)")
    return applied, skipped, names


def apply_all_arm64_patches(data, *, arm64_only: bool = True) -> Tuple[int, int, List[str]]:
    if not isinstance(data, bytearray):
        data = bytearray(data)
    a1, s1, n1 = apply_macos_stereo_patches(data, arm64_only=arm64_only)
    # Track touched RANGES so the dynamic scans can't trample a static patch
    # site (the previous flat `set[int]` of start offsets could not protect
    # 4-byte regions inside an 8-byte MOVZ+literal site).
    touched_ranges: List[Tuple[int, int]] = []
    for p in find_macos_stereo_patches(data):
        if p.get("mismatch"):
            continue
        fo = p["fat_offset"]
        patch_len = len(_hex_bytes(p["patch"]))
        touched_ranges.append((fo, patch_len))
    a2, n2 = _scan_arm64_bitrate_literals(data, touched_ranges)
    a3, n3 = _scan_arm64_movz_32000(data, touched_ranges)
    return a1 + a2 + a3, s1, n1 + n2 + n3


# Discord-themed colors (matches DiscordStereoPatcher)
COLORS = {
    "bg_dark": "#1e1f22",
    "bg_secondary": "#2b2d31",
    "bg_tertiary": "#313338",
    "bg_input": "#383a40",
    "text_normal": "#dbdee1",
    "text_muted": "#949ba4",
    "text_header": "#f2f3f5",
    "blurple": "#5865f2",
    "blurple_dark": "#4752c4",
    "green": "#57f287",
    "red": "#ed4245",
    "yellow": "#fee75c",
    "white": "#ffffff",
}

CACHE_DIR = Path.home() / "Library" / "Caches" / "DiscordVoicePatcher"


def app_data_dir() -> Path:
    return Path.home() / "Library" / "Application Support" / "DiscordArm64StereoPatcher"


# M5: canonical backup root. Previously this was `CACHE_DIR / "Backups"`, which
# disagreed with `backup_path_for()` (which used `app_data_dir() / "backups"`)
# — the GUI's "Open in Finder" pointed at a folder the patcher never wrote to.
# Now both point at the same canonical location.
BACKUP_DIR = app_data_dir() / "backups"
# Legacy backup root from older patcher versions — still scanned by list_backups
# so users can restore backups made before this consolidation.
LEGACY_BACKUP_DIR = CACHE_DIR / "Backups"



BADGE_GREEN_BG = "#1a3328"
BADGE_GREEN_FG = "#3dd68c"
BADGE_YELLOW_BG = "#3d3520"
BADGE_YELLOW_FG = "#fbbf24"
LOG_BG = "#111214"
CARD_BORDER = "#3f4147"
RADIUS_CARD = 12
RADIUS_BTN = 8
RADIUS_INPUT = 8
RADIUS_BADGE = 14
RADIUS_LOG = 10
RADIUS_PROGRESS = 5
CARD_BORDER_WIDTH = 1


def _rounded_inset(radius: int) -> int:
    """Keep embedded rectangular windows off the curved corner band."""
    return CARD_BORDER_WIDTH + max(radius - CARD_BORDER_WIDTH, 0)


def _draw_rounded_panel(
    canvas,
    w: int,
    h: int,
    radius: int,
    *,
    fill: str,
    border: str = CARD_BORDER,
    tag: str = "",
) -> None:
    inner_r = max(radius - CARD_BORDER_WIDTH, 0)
    _draw_round_rect(canvas, 0, 0, w, h, radius, fill=border, outline="", tags=tag)
    _draw_round_rect(
        canvas,
        CARD_BORDER_WIDTH,
        CARD_BORDER_WIDTH,
        w - CARD_BORDER_WIDTH,
        h - CARD_BORDER_WIDTH,
        inner_r,
        fill=fill,
        outline="",
        tags=tag,
    )


def _ui_font(size: int = 10, bold: bool = False) -> Tuple[str, int, str]:
    family = "SF Pro Text" if sys.platform == "darwin" else "Segoe UI"
    return (family, size, "bold" if bold else "normal")


def _ui_font_display(size: int = 22) -> Tuple[str, int, str]:
    family = "SF Pro Display" if sys.platform == "darwin" else "Segoe UI"
    return (family, size, "bold")


def _mono_font(size: int = 10) -> Tuple[str, int]:
    family = "SF Mono" if sys.platform == "darwin" else "Consolas"
    return (family, size)


def _short_home_path(p: Path) -> str:
    try:
        home = str(Path.home())
        s = str(p)
        if s.startswith(home):
            return "~" + s[len(home) :]
        return s
    except Exception:
        return str(p)


def _parent_bg(widget) -> str:
    try:
        return widget.cget("bg")
    except Exception:
        return COLORS["bg_dark"]


def _draw_round_rect(canvas, x1, y1, x2, y2, radius, *, fill, outline="", width=0, tags="") -> int:
    """Solid rounded rectangle using arcs + rectangles (crisp corners)."""
    r = max(0, min(radius, (x2 - x1) / 2, (y2 - y1) / 2))
    kw: dict = {"fill": fill, "outline": outline or fill, "width": width}
    if tags:
        kw["tags"] = tags
    if r <= 0:
        return canvas.create_rectangle(x1, y1, x2, y2, **kw)
    canvas.create_rectangle(x1 + r, y1, x2 - r, y2, **kw)
    canvas.create_rectangle(x1, y1 + r, x2, y2 - r, **kw)
    for cx, cy in ((x1, y1), (x2 - 2 * r, y1), (x1, y2 - 2 * r), (x2 - 2 * r, y2 - 2 * r)):
        canvas.create_oval(cx, cy, cx + 2 * r, cy + 2 * r, **kw)
    return 0


def _measure_text(text: str, font) -> Tuple[int, int]:
    try:
        import tkinter.font as tkfont

        f = tkfont.Font(font=font)
        return f.measure(text) + 28, f.metrics("linespace") + 16
    except Exception:
        return max(len(text) * 7 + 28, 80), 34


class ThemedButton(tk.Canvas):
    """Rounded canvas button — works on macOS and Windows."""

    def __init__(
        self,
        parent,
        text: str,
        bg: str,
        hover: str,
        command,
        *,
        fg: str = "#ffffff",
        radius: int = RADIUS_BTN,
    ) -> None:
        pbg = _parent_bg(parent)
        w, h = _measure_text(text, _ui_font(10))
        super().__init__(
            parent,
            width=w,
            height=h,
            bg=pbg,
            highlightthickness=0,
            bd=0,
            cursor="hand2",
        )
        self._text = text
        self._base_bg = bg
        self._hover_bg = hover
        self._cur_bg = bg
        self._command = command
        self._enabled = True
        self._fg = fg
        self._disabled_bg = COLORS["bg_tertiary"]
        self._disabled_fg = COLORS["text_muted"]
        self._radius = radius
        self.bind("<Button-1>", self._click)
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)
        self.bind("<Configure>", lambda _e: self._draw())
        self._draw()

    def _draw(self) -> None:
        self.delete("all")
        w = max(self.winfo_width(), 4)
        h = max(self.winfo_height(), 4)
        _draw_rounded_panel(self, w, h, self._radius, fill=self._cur_bg)
        self.create_text(
            w / 2,
            h / 2,
            text=self._text,
            fill=self._fg if self._enabled else self._disabled_fg,
            font=_ui_font(10),
        )

    def _click(self, _event=None) -> None:
        if self._enabled:
            self._command()

    def _enter(self, _event=None) -> None:
        if self._enabled:
            self._cur_bg = self._hover_bg
            self._draw()

    def _leave(self, _event=None) -> None:
        if self._enabled:
            self._cur_bg = self._base_bg
            self._draw()

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self._cur_bg = self._base_bg if enabled else self._disabled_bg
        self.configure(cursor="hand2" if enabled else "arrow")
        self._draw()


class SectionCard(tk.Frame):
    """Rounded section panel with title and body area."""

    def __init__(self, parent, title: str, *, radius: int = RADIUS_CARD) -> None:
        super().__init__(parent, bg=COLORS["bg_dark"])
        self._radius = radius
        self.canvas = tk.Canvas(self, bg=COLORS["bg_dark"], highlightthickness=0, bd=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)

        self.inner = tk.Frame(self.canvas, bg=COLORS["bg_secondary"])
        tk.Label(
            self.inner,
            text=title,
            bg=COLORS["bg_secondary"],
            fg=COLORS["text_muted"],
            font=_ui_font(10, True),
            anchor=tk.W,
        ).pack(fill=tk.X, padx=16, pady=(14, 8))
        self.body = tk.Frame(self.inner, bg=COLORS["bg_secondary"])
        self.body.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 16))

        inset = _rounded_inset(self._radius)
        self._inset = inset
        self._win = self.canvas.create_window(inset, inset, anchor=tk.NW, window=self.inner)
        self.canvas.bind("<Configure>", self._paint)

    def _paint(self, _event=None) -> None:
        w = max(self.canvas.winfo_width(), 4)
        h = max(self.canvas.winfo_height(), 4)
        self.canvas.delete("card")
        _draw_rounded_panel(
            self.canvas,
            w,
            h,
            self._radius,
            fill=COLORS["bg_secondary"],
            tag="card",
        )
        self.canvas.tag_lower("card")
        inset = self._inset
        inner_w = max(w - inset * 2, 1)
        inner_h = max(h - inset * 2, 1)
        self.canvas.coords(self._win, inset, inset)
        self.canvas.itemconfigure(self._win, width=inner_w, height=inner_h)


class RoundedLogPanel(tk.Frame):
    """Log console with rounded border."""

    def __init__(self, parent) -> None:
        super().__init__(parent, bg=COLORS["bg_secondary"])
        self.canvas = tk.Canvas(self, bg=COLORS["bg_secondary"], highlightthickness=0, bd=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self._radius = RADIUS_LOG

        wrap = tk.Frame(self.canvas, bg=LOG_BG)
        scroll = tk.Scrollbar(
            wrap,
            bg=COLORS["bg_tertiary"],
            troughcolor=LOG_BG,
            activebackground=COLORS["bg_input"],
            highlightthickness=0,
            bd=0,
            width=12,
        )
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.text = tk.Text(
            wrap,
            wrap=tk.WORD,
            bg=LOG_BG,
            fg=COLORS["text_normal"],
            insertbackground=COLORS["text_normal"],
            font=_mono_font(10),
            relief=tk.FLAT,
            bd=0,
            highlightthickness=0,
            height=14,
            yscrollcommand=scroll.set,
        )
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.config(command=self.text.yview)

        inset = _rounded_inset(self._radius)
        self._inset = inset
        self._win = self.canvas.create_window(inset, inset, anchor=tk.NW, window=wrap)
        self.canvas.bind("<Configure>", self._paint)

    def _paint(self, _event=None) -> None:
        w = max(self.canvas.winfo_width(), 4)
        h = max(self.canvas.winfo_height(), 4)
        self.canvas.delete("logbg")
        _draw_rounded_panel(self.canvas, w, h, self._radius, fill=LOG_BG, tag="logbg")
        self.canvas.tag_lower("logbg")
        inset = self._inset
        inner_w = max(w - inset * 2, 1)
        inner_h = max(h - inset * 2, 1)
        self.canvas.coords(self._win, inset, inset)
        self.canvas.itemconfigure(self._win, width=inner_w, height=inner_h)


def _badge(parent, text: str, bg: str, fg: str) -> tk.Canvas:
    pbg = _parent_bg(parent)
    w, h = _measure_text(text, _ui_font(9))
    h = max(h - 4, 26)
    c = tk.Canvas(parent, width=w, height=h, bg=pbg, highlightthickness=0, bd=0)

    def _draw() -> None:
        c.delete("all")
        ww = max(c.winfo_width(), w)
        hh = max(c.winfo_height(), h)
        _draw_rounded_panel(c, ww, hh, RADIUS_BADGE, fill=bg, border=bg)
        c.create_text(ww / 2, hh / 2, text=text, fill=fg, font=_ui_font(9))

    c.bind("<Configure>", lambda _e: _draw())
    _draw()
    return c


class ProgressBar(tk.Frame):
    def __init__(self, parent) -> None:
        super().__init__(parent, bg=COLORS["bg_secondary"])
        self._pct = 0.0
        self._canvas = tk.Canvas(self, height=8, bg=COLORS["bg_secondary"], highlightthickness=0, bd=0)
        self._canvas.pack(fill=tk.X)
        self._canvas.bind("<Configure>", lambda _e: self._draw())

    def set(self, pct: float) -> None:
        self._pct = max(0.0, min(100.0, pct))
        self._draw()

    def _draw(self) -> None:
        try:
            self._canvas.delete("all")
            w = max(self._canvas.winfo_width(), 1)
            h = 8
            _draw_round_rect(self._canvas, 0, 1, w, h - 1, RADIUS_PROGRESS, fill=COLORS["bg_input"], outline="")
            fill = int((w - 2) * self._pct / 100.0)
            if fill > 4:
                _draw_round_rect(self._canvas, 1, 2, 1 + fill, h - 2, RADIUS_PROGRESS, fill=COLORS["green"], outline="")
        except Exception:
            pass


class DarkDropdown(tk.Frame):
    def __init__(self, parent, variable: tk.StringVar, on_select=None) -> None:
        super().__init__(parent, bg=COLORS["bg_secondary"])
        self.var = variable
        self._values: List[str] = []
        self._on_select = on_select
        self.canvas = tk.Canvas(self, height=38, bg=COLORS["bg_secondary"], highlightthickness=0, bd=0)
        self.canvas.pack(fill=tk.X, expand=True)

        self.inner = tk.Frame(self.canvas, bg=COLORS["bg_input"])
        self.label = tk.Label(
            self.inner,
            textvariable=variable,
            bg=COLORS["bg_input"],
            fg=COLORS["text_normal"],
            font=_mono_font(10),
            anchor=tk.W,
            padx=12,
            pady=8,
        )
        self.label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(
            self.inner,
            text="▾",
            bg=COLORS["bg_input"],
            fg=COLORS["text_muted"],
            padx=10,
        ).pack(side=tk.RIGHT)

        inset = _rounded_inset(RADIUS_INPUT)
        self._inset = inset
        self._win = self.canvas.create_window(inset, inset, anchor=tk.NW, window=self.inner)
        for widget in (self.canvas, self.inner, self.label):
            widget.bind("<Button-1>", self._open_menu)
        self.canvas.bind("<Configure>", self._paint)
        variable.trace_add("write", lambda *_: self._paint())

    def _paint(self, _event=None) -> None:
        w = max(self.canvas.winfo_width(), 4)
        h = max(self.canvas.winfo_height(), 38)
        self.canvas.delete("dd")
        _draw_rounded_panel(self.canvas, w, h, RADIUS_INPUT, fill=COLORS["bg_input"], tag="dd")
        self.canvas.tag_lower("dd")
        inset = self._inset
        self.canvas.coords(self._win, inset, inset)
        self.canvas.itemconfigure(
            self._win,
            width=max(w - inset * 2, 1),
            height=max(h - inset * 2, 1),
        )

    def set_values(self, values: List[str]) -> None:
        self._values = list(values)

    def _open_menu(self, _event=None) -> None:
        if not self._values:
            return
        menu = tk.Menu(
            self,
            tearoff=0,
            bg=COLORS["bg_input"],
            fg=COLORS["text_normal"],
            activebackground=COLORS["blurple"],
            activeforeground=COLORS["white"],
            borderwidth=0,
        )
        for value in self._values:
            menu.add_command(label=value, command=lambda v=value: self._pick(v))
        try:
            menu.tk_popup(self.winfo_rootx(), self.winfo_rooty() + self.winfo_height())
        finally:
            menu.grab_release()

    def _pick(self, value: str) -> None:
        self.var.set(value)
        if self._on_select:
            self._on_select()



def log_path() -> Path:
    return app_data_dir() / "arm64_stereo_patcher.log"


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def human_exc(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}"


_DISCORD_CLIENTS = (
    ("discordcanary", "Discord Canary", "Discord Canary.app"),
    ("discordptb", "Discord PTB", "Discord PTB.app"),
    ("discorddevelopment", "Discord Development", "Discord Development.app"),
    ("discord", "Discord", "Discord.app"),
)


def resolve_client_from_node(node: Path) -> Tuple[str, str, str]:
    s = str(node).lower()
    for key, app_name, bundle in _DISCORD_CLIENTS:
        if f"/{key}/" in s or f"application support/{key}" in s:
            return key, app_name, bundle
    return "discord", "Discord", "Discord.app"


def _lsof_holders(path: Path) -> list[str]:
    if sys.platform != "darwin":
        return []
    try:
        r = subprocess.run(["lsof", "-t", str(path)], capture_output=True, text=True, check=False)
    except Exception:
        return []
    if r.returncode != 0:
        return []
    return [line.strip() for line in r.stdout.splitlines() if line.strip()]


def is_file_in_use(path: Path) -> bool:
    return bool(_lsof_holders(path))


def _pgrep_match(pattern: str) -> bool:
    try:
        r = subprocess.run(["pgrep", "-if", pattern], capture_output=True, text=True, check=False)
    except Exception:
        return False
    return r.returncode == 0


def is_discord_running_for_node(node: Path) -> bool:
    key, app_name, bundle = resolve_client_from_node(node)
    for pattern in (bundle, app_name, f"Application Support/{key}"):
        if _pgrep_match(pattern):
            return True
    return False


def close_discord_for_node(node: Path, log: LogSink) -> None:
    if sys.platform != "darwin":
        return
    key, app_name, _bundle = resolve_client_from_node(node)
    running = is_discord_running_for_node(node)
    locked = is_file_in_use(node)
    if not running and not locked:
        log.ok("Discord is not running")
        return

    log.info(f"Closing {app_name}...")
    subprocess.run(
        ["osascript", "-e", f'tell application "{app_name}" to quit'],
        capture_output=True,
        text=True,
        check=False,
    )
    subprocess.run(["killall", app_name], capture_output=True, text=True, check=False)
    subprocess.run(["pkill", "-f", f"Application Support/{key}"], capture_output=True, text=True, check=False)

    for _ in range(24):
        if not is_file_in_use(node) and not is_discord_running_for_node(node):
            time.sleep(0.5)
            log.ok("Discord closed")
            return
        time.sleep(0.25)

    log.warn("Discord did not exit cleanly — forcing...")
    subprocess.run(["pkill", "-9", "-f", f"Application Support/{key}"], capture_output=True, text=True, check=False)
    subprocess.run(["killall", "-9", app_name], capture_output=True, text=True, check=False)
    for pid in _lsof_holders(node):
        try:
            subprocess.run(["kill", "-9", pid], capture_output=True, text=True, check=False)
        except Exception:
            pass
    time.sleep(0.5)

    if is_file_in_use(node) or is_discord_running_for_node(node):
        raise RuntimeError(
            f"Could not close {app_name}. The voice module is still in use.\n"
            f"Quit Discord from the menu bar (or Activity Monitor) and try again."
        )
    log.ok("Discord closed")


def relaunch_discord_for_node(node: Path, log: LogSink) -> None:
    if sys.platform != "darwin":
        return
    _key, app_name, bundle = resolve_client_from_node(node)
    try:
        r = subprocess.run(["open", "-a", app_name], capture_output=True, text=True, check=False)
        if r.returncode == 0:
            log.ok(f"Relaunched {app_name}")
            return
    except Exception:
        pass
    for app_path in (Path("/Applications") / bundle, Path.home() / "Applications" / bundle):
        if app_path.is_dir():
            subprocess.run(["open", str(app_path)], check=False)
            log.ok(f"Relaunched {app_path}")
            return
    log.warn(f"Could not relaunch {app_name} automatically — open it manually.")


def discover_discord_installations() -> List[Tuple[str, str]]:
    """Discover installed Discord voice.node files.

    M8: deterministic — for each client we now sort every `discord_voice.node`
    match by mtime descending and pick the newest (rather than relying on the
    OS-dependent order from `rglob(...).next()`). Also includes Discord
    Development, which the previous list missed.
    """
    search = [
        ("Discord Stable", Path.home() / "Library/Application Support/discord"),
        ("Discord Canary", Path.home() / "Library/Application Support/discordcanary"),
        ("Discord PTB", Path.home() / "Library/Application Support/discordptb"),
        ("Discord Development", Path.home() / "Library/Application Support/discorddevelopment"),
    ]
    found: List[Tuple[str, str]] = []
    for name, base in search:
        if not base.is_dir():
            continue
        matches = [p for p in base.rglob("discord_voice.node") if p.is_file()]
        if not matches:
            continue
        # Sort newest first by mtime so an upgrade leaves the old copy behind.
        matches.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        newest = matches[0]
        found.append((name, str(newest)))
    return found


# ----------------------------------------------------------------------------
# Voice module download / replacement workflow
# ----------------------------------------------------------------------------
#
# BUGFIX (download workflow): the previous version of this patcher had NO
# mechanism for downloading the unpatched discord_voice.node + sibling module
# files (index.js, libmediapipe.dylib, manifest.json, package.json,
# selfie_segmentation*.tflite) from the GitHub release folder. When the
# locally installed Discord build did not match PATCHES_META (size + SHA-256),
# `verify_node_identity` would fail and patching would abort with no fallback.
#
# The Windows patcher (Discord_voice_node_patcher.ps1) implements this via
# `Save-VoiceBackupFiles` + `Get-PreparedVoiceBackupPath` +
# `Invoke-PatchClients`. The functions below mirror that workflow for macOS:
#
#   1. `download_voice_backup_files(dest_dir, log)` — fetch the file list
#      from the GitHub contents API and download every file into `dest_dir`.
#   2. `prepare_voice_backup(log)` — wraps (1), verifies the downloaded
#      discord_voice.node matches PATCHES_META (size + SHA-256), and returns
#      the directory.
#   3. `get_voice_module_paths(node)` — resolves the discord_voice module
#      folder for a given discord_voice.node path (handles both flat and
#      nested `discord_voice-x/discord_voice/` layouts).
#   4. `install_voice_module(node, backup_dir, log)` — clears the existing
#      module folder (after backing it up) and copies the downloaded files
#      in, so the locally installed Discord build is downgraded to the
#      version the patcher's offsets target.
#
# `run_cli` and `PatcherApp._start_patch` both call `prepare_voice_backup`
# when `verify_node_identity` reports a size/hash mismatch.

# GitHub contents-API URL for the macOS unpatched-voice folder. URL-encoded
# "Updates/Nodes/Unpatched Nodes (For Patcher)/macOS".
VOICE_BACKUP_API_URL = (
    "https://api.github.com/repos/ProdHallow/Discord-Stereo-Windows-MacOS-Linux"
    "/contents/Updates%2FNodes%2FUnpatched%20Nodes%20%28For%20Patcher%29%2FmacOS"
)
VOICE_BACKUP_RAW_BASE = (
    "https://raw.githubusercontent.com/ProdHallow/Discord-Stereo-Windows-MacOS-Linux"
    "/main/Updates/Nodes/Unpatched%20Nodes%20%28For%20Patcher%29/macOS"
)

# Files we expect to find in the macOS unpatched-voice folder. We enforce this
# list so a partial / corrupt GitHub response doesn't leave the user with a
# half-populated module folder (which would crash Discord on launch).
VOICE_MODULE_REQUIRED_FILES = (
    "discord_voice.node",
    "index.js",
    "libmediapipe.dylib",
    "manifest.json",
    "package.json",
    "selfie_segmentation.tflite",
    "selfie_segmentation_landscape.tflite",
)


def _voice_backup_cache_dir() -> Path:
    """Where to store downloaded voice-module files across runs."""
    return CACHE_DIR / "VoiceBackup_macOS"


def _http_get_json(url: str, *, timeout: float = 30.0) -> list:
    """GET a GitHub contents-API URL and return the parsed JSON list."""
    import json as _json
    import urllib.request
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "DiscordVoicePatcher",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    data = _json.loads(body.decode("utf-8"))
    if not isinstance(data, list):
        raise RuntimeError(
            f"GitHub API returned {type(data).__name__}, expected a list (rate limit?)"
        )
    return data


def _list_voice_backup_files_via_api() -> list:
    """List the macOS unpatched-voice folder via the GitHub contents API.

    Returns a list of dicts with at least: name, type, size, download_url.
    Raises on failure.
    """
    return _http_get_json(VOICE_BACKUP_API_URL)


def _list_voice_backup_files_via_raw() -> list:
    """Fallback: list the macOS unpatched-voice folder by fetching manifest.json
    directly from raw.githubusercontent.com (bypasses the contents API and its
    rate limit). Returns a list of dicts shaped like the API response.

    manifest.json contains a `files` array listing every expected file name.
    We HEAD each file via raw URL to get its size; if HEAD fails we leave
    size at 0 (download will still work, we just lose the size info).
    """
    import urllib.request
    manifest_url = f"{VOICE_BACKUP_RAW_BASE}/manifest.json"
    req = urllib.request.Request(
        manifest_url, headers={"User-Agent": "DiscordVoicePatcher"}
    )
    with urllib.request.urlopen(req, timeout=30.0) as r:
        body = r.read().decode("utf-8")
    import json as _json
    manifest = _json.loads(body)
    file_names = manifest.get("files") or list(VOICE_MODULE_REQUIRED_FILES)
    out = []
    for name in file_names:
        url = f"{VOICE_BACKUP_RAW_BASE}/{name}"
        size = 0
        # Best-effort HEAD to get Content-Length; harmless if it fails.
        try:
            head_req = urllib.request.Request(
                url, method="HEAD", headers={"User-Agent": "DiscordVoicePatcher"}
            )
            with urllib.request.urlopen(head_req, timeout=15.0) as hr:
                cl = hr.headers.get("Content-Length")
                if cl:
                    size = int(cl)
        except Exception:
            pass
        out.append({
            "name": name,
            "type": "file",
            "size": size,
            "download_url": url,
        })
    return out


def _http_download_file(url: str, dest: Path, *, timeout: float = 120.0) -> None:
    """Stream a binary file from `url` to `dest` (atomic via .tmp rename)."""
    import urllib.request
    tmp = dest.with_name(dest.name + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "DiscordVoicePatcher"})
    with urllib.request.urlopen(req, timeout=timeout) as r, tmp.open("wb") as f:
        while True:
            chunk = r.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
    os.replace(tmp, dest)


def download_voice_backup_files(dest_dir: Path, log: Optional[LogSink] = None) -> bool:
    """Download every file from the macOS unpatched-voice GitHub folder.

    Mirrors `Save-VoiceBackupFiles` in Discord_voice_node_patcher.ps1:
      1. Clears `dest_dir` (if it exists) so stale files don't linger.
      2. Lists the folder via the GitHub contents API.
      3. Downloads each `file` entry into `dest_dir`.
      4. Verifies that every file in VOICE_MODULE_REQUIRED_FILES is present
         and non-empty before returning True.
    """
    def _info(m: str) -> None:
        if log is not None:
            log.info(m)
    def _ok(m: str) -> None:
        if log is not None:
            log.ok(m)
    def _warn(m: str) -> None:
        if log is not None:
            log.warn(m)
    def _fail(m: str) -> None:
        if log is not None:
            log.fail(m)

    if dest_dir.exists():
        _info(f"Clearing existing backup folder: {_short_home_path(dest_dir)}")
        shutil.rmtree(dest_dir, ignore_errors=True)
    safe_mkdir(dest_dir)

    _info("Fetching file list from GitHub API...")
    entries: list = []
    try:
        entries = _list_voice_backup_files_via_api()
    except Exception as e:
        _warn(f"GitHub contents API failed ({human_exc(e)}); falling back to raw URLs")
        try:
            entries = _list_voice_backup_files_via_raw()
        except Exception as e2:
            _fail(f"Raw fallback also failed: {human_exc(e2)}")
            return False
    if not entries:
        _fail("GitHub repository response is empty.")
        return False

    file_entries = [e for e in entries if e.get("type") == "file"]
    if not file_entries:
        _fail("No files found in the macOS unpatched-voice folder.")
        return False

    _info(f"Found {len(file_entries)} file(s) to download")
    failed: List[str] = []
    for entry in file_entries:
        name = entry.get("name", "")
        if not name:
            continue
        url = entry.get("download_url") or f"{VOICE_BACKUP_RAW_BASE}/{name}"
        dest = dest_dir / name
        _info(f"  Downloading: {name} ({entry.get('size', '?')} bytes)")
        try:
            _http_download_file(url, dest)
            if not dest.is_file():
                raise RuntimeError("file was not created")
            size = dest.stat().st_size
            if size == 0:
                raise RuntimeError("downloaded file is empty")
            # Sanity-check the .node / .dylib: anything <1 KB is suspicious.
            ext = dest.suffix.lower()
            if ext in (".node", ".dylib") and size < 1024:
                _warn(f"  {name} seems too small ({size} bytes)")
        except Exception as e:
            _warn(f"  Failed to download {name}: {human_exc(e)}")
            failed.append(name)

    # Enforce that all required files are present.
    missing = [n for n in VOICE_MODULE_REQUIRED_FILES if not (dest_dir / n).is_file()]
    if missing:
        _fail(f"Missing required module files after download: {', '.join(missing)}")
        return False
    if failed:
        _warn(f"{len(failed)} file(s) failed to download (see log above)")
    _ok(f"Downloaded {len(file_entries) - len(failed)}/{len(file_entries)} voice backup files")
    return True


def prepare_voice_backup(log: Optional[LogSink] = None) -> Optional[Path]:
    """Download + verify the macOS unpatched voice module.

    Mirrors `Get-PreparedVoiceBackupPath` in the Windows patcher. Returns the
    backup directory on success, or None on failure.
    """
    backup_dir = _voice_backup_cache_dir()
    if not download_voice_backup_files(backup_dir, log):
        if log is not None:
            log.fail("Failed to download voice backup files")
        return None

    node_path = backup_dir / "discord_voice.node"
    if not node_path.is_file():
        if log is not None:
            log.fail(f"discord_voice.node was not found in voice backup folder: {backup_dir}")
        return None

    try:
        size = node_path.stat().st_size
        digest = sha256_file(node_path)
        if log is not None:
            log.info(
                f"Voice node downloaded: {size / (1024 * 1024):.2f} MB | SHA-256={digest}"
            )
        expected_size = PATCHES_META.get("file_size")
        if expected_size and size != expected_size:
            if log is not None:
                log.warn(
                    f"Downloaded node size ({size}) does not match PATCHES_META.file_size ({expected_size})"
                )
        expected_hash = str(PATCHES_META.get("sha256") or "").lower()
        if expected_hash and digest.lower() != expected_hash:
            if log is not None:
                log.fail("Downloaded discord_voice.node SHA-256 does NOT match PATCHES_META.sha256.")
                log.fail(f"  downloaded: {digest}")
                log.fail(f"  expected:   {expected_hash}")
                log.fail(
                    "  Either the GitHub folder published a different stock build, or "
                    "PATCHES_META needs to be recomputed. Refusing to install."
                )
            return None
    except Exception as e:
        if log is not None:
            log.warn(f"Could not verify downloaded voice node: {human_exc(e)}")
        # Soft-fail: keep going if size/hash check threw (matches Windows behavior).

    return backup_dir


def get_voice_module_paths(node: Path) -> dict:
    """Resolve the discord_voice module folder layout for a node path.

    macOS layouts observed in the wild:
      ~/Library/Application Support/discord/<app-version>/modules/
        discord_voice-<ver>/discord_voice.node                 (flat)
        discord_voice-<ver>/discord_voice/discord_voice.node   (nested)

    Returns a dict with:
      modules_root       : .../modules
      voice_module_root  : .../discord_voice-<ver>
      voice_folder       : the folder that directly contains discord_voice.node
      voice_node         : the node path itself
    Returns {} if the layout can't be determined.
    """
    node = Path(node)
    if not node.is_file():
        return {}
    voice_folder = node.parent
    voice_module_root = voice_folder
    # If the layout is nested (discord_voice-x/discord_voice/discord_voice.node),
    # the parent of voice_folder is the versioned module dir.
    if voice_folder.name == "discord_voice" and voice_folder.parent.name.startswith("discord_voice-"):
        voice_module_root = voice_folder.parent
    # Walk up to find the `modules` dir.
    modules_root: Optional[Path] = None
    for parent in voice_module_root.parents:
        if parent.name == "modules":
            modules_root = parent
            break
    return {
        "modules_root": modules_root,
        "voice_module_root": voice_module_root,
        "voice_folder": voice_folder,
        "voice_node": node,
    }


def _clear_directory_safe(path: Path) -> bool:
    """Remove every entry inside `path` (but keep `path` itself)."""
    if not path.is_dir():
        return False
    try:
        for child in path.iterdir():
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                try:
                    child.unlink()
                except OSError:
                    pass
        return True
    except Exception:
        return False


def install_voice_module(node: Path, backup_dir: Path, log: LogSink) -> bool:
    """Replace the voice-module folder with the downloaded files.

    Mirrors the Windows patcher's `Clear-DirectoryContentsSafe` + `Copy-Item`
    sequence: clear the existing folder, copy every file from `backup_dir`
    into it, then verify the new discord_voice.node is in place.

    The caller is responsible for closing Discord and (after this call) for
    patching + codesigning the freshly installed node.
    """
    paths = get_voice_module_paths(node)
    if not paths:
        log.fail(f"Could not resolve voice module layout for: {node}")
        return False
    voice_folder: Path = paths["voice_folder"]
    voice_module_root: Optional[Path] = paths.get("voice_module_root")

    # Snapshot the OLD module folder first — paranoid backup in case the
    # install fails midway. We do NOT rely on this for restore (the canonical
    # backup is `ensure_backup`), but it gives us a recovery path.
    snapshot_dir = CACHE_DIR / f"VoiceModuleSnapshot_{int(time.time())}"
    try:
        if voice_folder.is_dir():
            shutil.copytree(voice_folder, snapshot_dir, dirs_exist_ok=True)
            log.info(f"Snapshot of old module folder: {_short_home_path(snapshot_dir)}")
    except Exception as e:
        log.warn(f"Could not snapshot old module folder: {human_exc(e)}")

    log.info(f"Clearing existing voice module folder: {_short_home_path(voice_folder)}")
    if not _clear_directory_safe(voice_folder):
        # If we can't clear in place (rare), try removing the whole folder so
        # copytree can recreate it. This is more aggressive but matches what
        # the Windows patcher does with `Remove-Item -Recurse`.
        try:
            shutil.rmtree(voice_folder, ignore_errors=True)
            safe_mkdir(voice_folder)
        except Exception as e:
            log.fail(f"Could not clear voice module folder: {human_exc(e)}")
            return False

    log.info(f"Installing downloaded voice module files into: {_short_home_path(voice_folder)}")
    try:
        for src in sorted(backup_dir.iterdir()):
            if not src.is_file():
                continue
            dst = voice_folder / src.name
            shutil.copy2(src, dst)
            log.ok(f"  installed: {src.name} ({src.stat().st_size:,} bytes)")
    except Exception as e:
        log.fail(f"Failed to copy voice module files: {human_exc(e)}")
        # Try to restore from snapshot
        if snapshot_dir.is_dir():
            log.warn("Attempting to restore from snapshot...")
            try:
                _clear_directory_safe(voice_folder)
                for src in snapshot_dir.iterdir():
                    if src.is_file():
                        shutil.copy2(src, voice_folder / src.name)
            except Exception:
                pass
        return False

    # Verify install
    new_node = voice_folder / "discord_voice.node"
    if not new_node.is_file():
        log.fail("discord_voice.node is missing after install — aborting")
        return False

    expected_size = PATCHES_META.get("file_size")
    if expected_size and new_node.stat().st_size != expected_size:
        log.warn(
            f"Installed discord_voice.node size ({new_node.stat().st_size}) does not "
            f"match expected ({expected_size})"
        )

    log.ok("Voice module files replaced successfully")
    return True


def format_node_status_line(node_path: str) -> str:
    node = Path(node_path)
    if not node.is_file():
        return "Node file not found"
    ver = _version_from_node(node)
    state = check_patch_status(node_path)
    labels = {
        "unpatched": "Unpatched (original)",
        "patched": "Patched (stereo enabled)",
        "unknown": "Unknown version",
        "error": "Error reading file",
        "mismatch": "Mismatch — unexpected bytes at one or more sites",
    }
    size_mb = node.stat().st_size / (1024 * 1024)
    return f"v{ver} | {labels.get(state, state)} | {size_mb:.2f} MB"


def check_patch_status(node_path: str) -> str:
    try:
        state = _patch_state(Path(node_path))
        if state == "unpatched":
            return "unpatched"
        if state == "patched":
            return "patched"
        if state.startswith("mismatch"):
            # M2: surface mismatch as a first-class status.
            return "mismatch"
        if state in ("not found", "error"):
            return "error"
        return "unknown"
    except Exception:
        return "error"


def list_backups() -> List[Tuple[str, str, str]]:
    """Return (path, date, size) tuples — matches reference list_backups shape."""
    result: List[Tuple[str, str, str]] = []
    # M5: BACKUP_DIR is the canonical root; LEGACY_BACKUP_DIR catches backups
    # made by older patcher versions that wrote to Caches/DiscordVoicePatcher/Backups.
    roots = [BACKUP_DIR, LEGACY_BACKUP_DIR]
    seen = set()
    for root in roots:
        if not root.is_dir():
            continue
        files: List[Path] = []
        for pat in ("*.backup", "discord_voice.node.UNPATCHED"):
            files.extend(root.rglob(pat))
        for b in sorted(files, key=lambda p: p.stat().st_mtime, reverse=True):
            key = str(b.resolve())
            if key in seen or not b.is_file():
                continue
            seen.add(key)
            st = b.stat()
            date = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            size_mb = st.st_size / (1024 * 1024)
            result.append((str(b), date, f"{size_mb:.2f} MB"))
    return result


def _version_from_node(node: Path) -> str:
    m = re.search(r"/app-([0-9.]+)/modules/", str(node))
    if m:
        return m.group(1)
    for part in node.parts:
        if part.startswith("app-"):
            return part.replace("app-", "")
    return "unknown"


def _patch_state(node: Path) -> str:
    if not node.is_file():
        return "not found"
    try:
        data = node.read_bytes()
        patches = [p for p in find_macos_stereo_patches(data) if p.get("arch") == "arm64"]
        if not patches:
            return "unknown"
        patched = sum(1 for p in patches if p.get("already_patched"))
        mismatches = sum(1 for p in patches if p.get("mismatch"))
        total = len(patches)
        if mismatches > 0:
            # M2: surface mismatched sites as a distinct state.
            return f"mismatch ({mismatches}/{total} sites)"
        if patched == total:
            return "patched"
        if patched == 0:
            return "unpatched"
        return f"partial ({patched}/{total})"
    except Exception:
        return "unknown"


def backup_path_for(node: Path) -> Path:
    key = str(node.parent).replace("\\", "_").replace("/", "_").replace(":", "")
    return app_data_dir() / "backups" / key / "discord_voice.node.UNPATCHED"


def meta_path_for(node: Path) -> Path:
    key = str(node.parent).replace("\\", "_").replace("/", "_").replace(":", "")
    return app_data_dir() / "backups" / key / "meta.json"


def ensure_backup(node: Path, log: LogSink) -> Path:
    bd = backup_path_for(node)
    if bd.is_file():
        try:
            cur_hash = sha256_file(node)
            bak_hash = sha256_file(bd)
            # Fall back to the legacy "md5" key if a downstream tool hasn't migrated.
            expected = str(PATCHES_META.get("sha256") or PATCHES_META.get("md5") or "")
            # If the backup is incorrect (eg. accidentally captured a patched node),
            # but the current node matches the expected stock build, refresh it.
            if expected and cur_hash == expected and bak_hash != expected:
                shutil.copy2(node, bd)
                try:
                    os.chmod(bd, 0o600)
                except OSError:
                    pass
                log.ok(f"Backup refreshed (matched stock): {_short_home_path(bd)}")
            else:
                log.info(f"Backup already exists: {_short_home_path(bd)}")
        except Exception:
            log.info(f"Backup already exists: {_short_home_path(bd)}")
        return bd
    safe_mkdir(bd.parent)
    shutil.copy2(node, bd)
    try:
        # Minor: lock down backup file permissions.
        os.chmod(bd, 0o600)
    except OSError:
        pass
    log.ok(f"Backup saved: {_short_home_path(bd)}")
    return bd


def record_last_patch(node: Path) -> None:
    mp = meta_path_for(node)
    safe_mkdir(mp.parent)
    mp.write_text(json.dumps({"last_patch_utc": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")


def patch_node_file(
    node_path: Path, *, write: bool = True, out_data: Optional[list] = None
) -> tuple[int, int, list[str]]:
    """Apply all ARM64 patches to `node_path`.

    If `out_data` is provided (a list), the in-memory patched bytearray is
    appended to it so the caller can pass it to `codesign_node(fallback_data=...)`
    or `_report_patch_coverage(data=...)` without re-reading the 50 MB file.
    """
    data = bytearray(node_path.read_bytes())
    applied, skipped, names = apply_all_arm64_patches(data, arm64_only=True)
    if write and applied > 0:
        node_path.write_bytes(data)
    if out_data is not None:
        out_data.append(data)
    return applied, skipped, names


def restore_node_file(node_path: Path, log: LogSink) -> bool:
    bd = backup_path_for(node_path)
    if not bd.is_file():
        log.fail(f"No backup found for: {_short_home_path(node_path)}")
        log.fail(f"Expected backup at: {_short_home_path(bd)}")
        return False
    close_discord_for_node(node_path, log)
    shutil.copy2(bd, node_path)
    try:
        os.chmod(node_path, 0o644)
    except OSError:
        pass
    codesign_node(node_path, log)
    log.ok("Binary restored from backup")
    return True


def verify_node_identity(node: Path, log: Optional[LogSink] = None) -> bool:
    """M3: gate patching on file size + SHA-256 match against PATCHES_META.

    Returns True if the node matches the expected stock build (or if the
    expected values are missing — fail-open for size/hash only). Returns
    False and logs a clear error otherwise.
    """
    if not node.is_file():
        if log is not None:
            log.fail(f"File not found: {node}")
        return False
    expected_size = PATCHES_META.get("file_size")
    if expected_size:
        actual_size = node.stat().st_size
        if actual_size != expected_size:
            if log is not None:
                log.fail(
                    f"Size mismatch: {node} is {actual_size} bytes, "
                    f"expected {expected_size} (stock build)."
                )
            return False
    expected_hash = str(PATCHES_META.get("sha256") or PATCHES_META.get("md5") or "")
    if expected_hash:
        actual_hash = sha256_file(node)
        if actual_hash != expected_hash:
            if log is not None:
                log.fail(
                    f"Hash mismatch: {node} SHA-256 = {actual_hash}, "
                    f"expected {expected_hash}.\n"
                    "  Either this is a different Discord build, or the SHA-256 in "
                    "PATCHES_META needs to be recomputed for the current stock binary."
                )
            return False
    return True


def _print_cli_usage() -> None:
    print(f"Usage: {Path(sys.argv[0]).name} [options] <path/to/discord_voice.node>")
    print(f"       {Path(sys.argv[0]).name} --restore <path/to/discord_voice.node>")
    print(f"       {Path(sys.argv[0]).name} --download-voice <path/to/discord_voice.node>")
    print(f"       {Path(sys.argv[0]).name} --gui")
    print("")
    print("Options:")
    print("  --restore <path>          Restore the binary from backup, then re-sign.")
    print("  --download-voice <path>   Download the unpatched macOS voice module from")
    print("                            GitHub and replace the module folder at <path>,")
    print("                            then patch and re-sign. Use this when your local")
    print("                            Discord build no longer matches the patcher offsets.")
    print("  --gui, -g                 Launch the Tk GUI (default when no args are given).")
    print("  --help                    Show this help and exit.")
    print("  --version                 Print version and exit.")


def run_cli(argv: list[str]) -> int:
    # M11: everything except --gui/-g/no-args goes to CLI. Handle --help/--version.
    if not argv or argv[0] in ("--help", "-h", "-?"):
        _print_cli_usage()
        return 0
    if argv[0] in ("--version", "-V"):
        print(f"{APP_NAME} v{APP_VERSION}")
        return 0

    force_download = False
    if argv[0] == "--download-voice":
        if len(argv) < 2:
            print("Missing path for --download-voice", file=sys.stderr)
            return 1
        force_download = True
        argv = argv[1:]  # consume the flag, treat the next arg as node path

    if argv[0] == "--restore":
        if len(argv) < 2:
            print("Missing path for --restore", file=sys.stderr)
            return 1
        node_path = Path(argv[1])
        if not node_path.is_file():
            print(f"File not found: {node_path}", file=sys.stderr)
            return 1
    else:
        node_path = Path(argv[0])
        if not node_path.is_file():
            print(f"File not found: {node_path}", file=sys.stderr)
            return 1

    class _CliLog:
        def info(self, msg: str) -> None:
            print(msg)

        def ok(self, msg: str) -> None:
            print(f"OK: {msg}")

        def warn(self, msg: str) -> None:
            print(f"WARN: {msg}", file=sys.stderr)

        def fail(self, msg: str) -> None:
            print(f"FAIL: {msg}", file=sys.stderr)

    log = _CliLog()

    if argv[0] == "--restore":
        try:
            ok = restore_node_file(node_path, log)
            return 0 if ok else 1
        except Exception as e:
            print(f"FAIL: {e}", file=sys.stderr)
            return 1

    # --download-voice: forcibly download + install the matching unpatched
    # voice module from GitHub before patching. This is the explicit
    # counterpart to the implicit "offer to download" path triggered when
    # verify_node_identity fails.
    did_kill_discord = False
    if force_download:
        print("=== Voice Module Download & Install (forced) ===")
        backup_dir = prepare_voice_backup(log)
        if backup_dir is None:
            print("Aborting: voice backup download/verify failed.", file=sys.stderr)
            return 2
        try:
            close_discord_for_node(node_path, log)
            did_kill_discord = True
        except Exception as e:
            print(f"FAIL: {e}", file=sys.stderr)
            return 1
        if not install_voice_module(node_path, backup_dir, log):
            print("Aborting: voice module install failed.", file=sys.stderr)
            return 1
        if not verify_node_identity(node_path, log):
            print(
                "Aborting: freshly installed discord_voice.node still does not match "
                "PATCHES_META.",
                file=sys.stderr,
            )
            return 2
        # Fall through to the normal patch flow.

    # M3: verify the binary matches the expected stock build before patching.
    # If it doesn't (and --download-voice wasn't already used), offer to
    # download + install the matching unpatched voice module from the GitHub
    # release folder (mirrors the Windows patcher's
    # `Get-PreparedVoiceBackupPath` + `Invoke-PatchClients` workflow).
    if "did_kill_discord" not in locals():
        did_kill_discord = False
    if not verify_node_identity(node_path, log):
        print(
            "\nThis discord_voice.node does not match the build the patcher's "
            "offsets target.\n"
            "Discord may have auto-updated to a newer build. The patcher can "
            "download the\nmatching UNPATCHED voice module from GitHub and "
            "replace your current module folder.\nThis will DOWNGRADE your "
            "Discord voice module to the version the patcher supports."
        )
        answer = input("\nDownload and install the matching voice module? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted. No changes were made.", file=sys.stderr)
            return 2

        backup_dir = prepare_voice_backup(log)
        if backup_dir is None:
            print("Aborting: voice backup download/verify failed.", file=sys.stderr)
            return 2

        # Close Discord before we touch the module folder.
        try:
            close_discord_for_node(node_path, log)
            did_kill_discord = True
        except Exception as e:
            print(f"FAIL: {e}", file=sys.stderr)
            return 1

        if not install_voice_module(node_path, backup_dir, log):
            print("Aborting: voice module install failed.", file=sys.stderr)
            return 1

        # Re-verify the freshly installed node. The path is the same — the
        # file inside that folder has been replaced.
        if not verify_node_identity(node_path, log):
            print(
                "Aborting: freshly installed discord_voice.node STILL does not match "
                "PATCHES_META. This should never happen — please report it.",
                file=sys.stderr,
            )
            return 2

    # Track whether we killed Discord so the finally block can relaunch it.
    try:
        try:
            ensure_backup(node_path, log)
            if is_discord_running_for_node(node_path) or is_file_in_use(node_path):
                did_kill_discord = True
            close_discord_for_node(node_path, log)
        except RuntimeError as e:
            print(f"FAIL: {e}", file=sys.stderr)
            return 1

        # M4: wrap the entire patch / codesign / bypass sequence so any failure
        # is logged cleanly and we still relaunch Discord in finally.
        try:
            out_data: list = []
            applied, skipped, names = patch_node_file(node_path, out_data=out_data)
            patched_bytes = out_data[0] if out_data else None
            if applied == 0 and skipped == 0:
                return 1
            if applied > 0:
                codesign_node(node_path, log, fallback_data=patched_bytes)
                enable_library_validation_bypass(node_path, log)
                _report_patch_coverage(
                    node_path, log, applied=applied, data=patched_bytes
                )
                print(f"  Applied {applied} ARM64 patches (stereo + bitrate + filters)")
                for n in names:
                    if not n.endswith("(already)") and not n.endswith("(mismatch)"):
                        print(f"    - {n}")
            elif skipped > 0:
                _report_patch_coverage(node_path, log, applied=0)
                print(f"  ARM64 stereo patches already applied ({skipped} sites checked)")
            return 0
        except Exception as e:
            print(f"FAIL: {e}", file=sys.stderr)
            return 1
    finally:
        # M4: always relaunch Discord if we killed it (or even if we didn't —
        # `open -a Discord` is idempotent and brings the running app forward).
        if did_kill_discord:
            try:
                relaunch_discord_for_node(node_path, log)
            except Exception:
                pass


def _refresh_node_inode(node: Path, fallback_data: Optional[bytes] = None) -> None:
    """Replace the node with a fresh inode (defeats macOS code-signature cache).

    Atomic on the same filesystem. On failure, restores the original bytes
    from `fallback_data` (the in-memory patched bytearray) so the binary is
    never left missing.
    """
    tmp = node.with_name(node.name + ".tmp_inode")
    try:
        shutil.copy2(node, tmp)
        os.replace(tmp, node)  # atomic; gives node a new inode
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        if fallback_data is not None:
            # Last resort: rewrite the original bytes so the binary still exists.
            node.write_bytes(fallback_data)
        raise


def enable_library_validation_bypass(node: Path, log: LogSink) -> bool:
    """Allow Discord to dlopen our ad-hoc signed discord_voice.node on Apple Silicon.

    M1: the bundle is resolved from `node` (so PTB / Canary / Development get
    the right app), not hardcoded to /Applications/Discord.app.
    """
    if sys.platform != "darwin":
        return True
    _key, _app_name, bundle = resolve_client_from_node(node)
    app_path = next(
        (p for p in (Path("/Applications") / bundle, Path.home() / "Applications" / bundle) if p.is_dir()),
        None,
    )
    if app_path is None:
        log.warn(f"{bundle} not found — skipping library-validation bypass")
        return False

    frameworks = app_path / "Contents" / "Frameworks"
    helper_bundles = [
        ("Discord Helper (GPU)", frameworks / "Discord Helper (GPU).app"),
        ("Discord Helper (Plugin)", frameworks / "Discord Helper (Plugin).app"),
        ("Discord Helper (Renderer)", frameworks / "Discord Helper (Renderer).app"),
    ]
    all_ok = True
    for name, bundle_path in helper_bundles:
        binary_path = bundle_path / "Contents" / "MacOS" / name
        if not binary_path.is_file():
            continue
        r = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", str(binary_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if not r.stdout.strip():
            continue
        ent_file = Path.home() / "Library" / "Caches" / "DiscordVoicePatcher" / f"ent_{name.replace(' ', '_')}.plist"
        ent_file.parent.mkdir(parents=True, exist_ok=True)
        ent_file.write_text(r.stdout, encoding="utf-8")
        for cmd in (
            ["Add", ":com.apple.security.cs.disable-library-validation", "bool", "true"],
            ["Set", ":com.apple.security.cs.disable-library-validation", "true"],
        ):
            pb = subprocess.run(
                ["/usr/libexec/PlistBuddy", "-c", " ".join(cmd), str(ent_file)],
                capture_output=True,
                text=True,
                check=False,
            )
            if pb.returncode == 0:
                break
        sr = subprocess.run(
            ["codesign", "--force", "--sign", "-", "--options", "runtime", "--entitlements", str(ent_file), str(bundle_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if sr.returncode == 0:
            log.ok(f"{name}: disable-library-validation added")
        else:
            log.warn(f"{name}: re-sign failed — {sr.stderr.strip() or sr.stdout.strip()}")
            if "not permitted" in (sr.stderr or "").lower():
                log.warn("Grant App Management permission in System Settings > Privacy & Security")
            all_ok = False

    main_binary = app_path / "Contents" / "MacOS" / "Discord"
    if all_ok and main_binary.is_file():
        r = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", str(main_binary)],
            capture_output=True,
            text=True,
            check=False,
        )
        ent_file = Path.home() / "Library" / "Caches" / "DiscordVoicePatcher" / "ent_Discord_main.plist"
        ent_file.write_text(r.stdout, encoding="utf-8")
        for cmd in (
            ["Add", ":com.apple.security.cs.disable-library-validation", "bool", "true"],
            ["Set", ":com.apple.security.cs.disable-library-validation", "true"],
        ):
            pb = subprocess.run(
                ["/usr/libexec/PlistBuddy", "-c", " ".join(cmd), str(ent_file)],
                capture_output=True,
                text=True,
                check=False,
            )
            if pb.returncode == 0:
                break
        sr = subprocess.run(
            ["codesign", "--force", "--sign", "-", "--options", "runtime", "--entitlements", str(ent_file), str(app_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if sr.returncode == 0:
            log.ok(f"{app_path.name} re-signed (library-validation bypass)")
        else:
            log.warn(f"{app_path.name} re-sign failed — {sr.stderr.strip() or sr.stdout.strip()}")
            all_ok = False

    if all_ok:
        subprocess.run(["xattr", "-cr", str(app_path)], capture_output=True, text=True, check=False)
    return all_ok


def codesign_node(node: Path, log: LogSink, *, fallback_data: Optional[bytes] = None) -> None:
    """Ad-hoc codesign the node.

    `fallback_data` is the in-memory patched bytearray from `patch_node_file`.
    If the inode refresh fails midway, _refresh_node_inode uses it to restore
    the binary so the user is never left with a missing discord_voice.node.
    """
    if sys.platform != "darwin":
        return
    try:
        _refresh_node_inode(node, fallback_data=fallback_data)
        subprocess.run(["codesign", "--remove-signature", str(node)], capture_output=True, text=True, check=False)
        r = subprocess.run(
            ["codesign", "--force", "--sign", "-", str(node)],
            capture_output=True,
            text=True,
            check=False,
        )
        subprocess.run(["xattr", "-cr", str(node)], capture_output=True, text=True, check=False)
        if r.returncode == 0:
            log.ok("Ad-hoc codesign completed")
            vr = subprocess.run(
                ["codesign", "--verify", "--verbose", str(node)],
                capture_output=True,
                text=True,
                check=False,
            )
            if vr.returncode != 0:
                log.warn(f"codesign verify failed: {(vr.stderr or vr.stdout or '').strip()}")
        else:
            err = (r.stderr or r.stdout or "").strip()
            # CRITICAL FIX 2: a failed codesign leaves the binary unusable.
            # This is a hard failure, not a warning.
            log.fail(f"codesign failed: {err or 'unknown error'}")
            raise RuntimeError(f"codesign failed: {err or 'unknown error'}")
    except RuntimeError:
        # Re-raise the codesign failure so callers can abort cleanly.
        raise
    except Exception as e:
        # CRITICAL FIX 2: surface unexpected errors as failures, not silent warns.
        log.fail(f"codesign error: {human_exc(e)}")
        raise


def _report_patch_coverage(
    node: Path, log: LogSink, *, applied: int, data: Optional[bytes] = None
) -> None:
    # M6: accept the in-memory patched `data` so we don't re-read the 50 MB file
    # on every call. Only the immediate post-patch call passes it; other call
    # sites that don't have the bytearray handy fall back to re-reading.
    if data is None:
        data = node.read_bytes()
    missing = missing_arm64_stereo_patch_names(data)
    found = [p for p in find_macos_stereo_patches(data) if p.get("arch") == "arm64"]
    patched_n = sum(1 for p in found if p.get("already_patched"))
    mismatch_n = sum(1 for p in found if p.get("mismatch"))
    log.info("")
    log.info(f"Coverage: {patched_n}/{len(ARM64_STEREO_SPEC_NAMES)} spec sites present on disk")
    if mismatch_n:
        log.warn(f"Mismatch at {mismatch_n} site(s) — unexpected bytes (not orig, not patched).")
    if missing:
        log.warn(f"Missing {len(missing)} patch site(s) — stereo may not work until these are found:")
        for name in missing:
            log.warn(f"  - {name}")
    if applied > 0 and patched_n < len(ARM64_STEREO_SPEC_NAMES) - 1:
        log.warn(
            "Incomplete patch set. Restore from UNPATCHED backup, update the patcher, and patch again with Discord fully quit."
        )


def scan_patches(node: Path, log: LogSink) -> list:
    patches = find_macos_stereo_patches(node.read_bytes())
    arm = [p for p in patches if p.get("arch") == "arm64"]
    log.info(f"Found {len(arm)} ARM64 stereo patch site(s) in fat binary")
    for p in arm[:30]:
        log.info(f"  {p['name']} @ 0x{p['fat_offset']:X}  {p['orig']} -> {p['patch']}")
    if len(arm) > 30:
        log.info(f"  ... and {len(arm) - 30} more")
    return arm


def _write_node_bytes(node: Path, data: bytes | bytearray, log: LogSink) -> None:
    if is_file_in_use(node):
        raise RuntimeError("discord_voice.node is locked — close Discord and try again.")
    node.write_bytes(data)
    log.ok("Binary patched on disk")


def verify_patches(node: Path, log: LogSink) -> None:
    data = node.read_bytes()
    patches = [p for p in find_macos_stereo_patches(data) if p.get("arch") == "arm64"]
    if not patches:
        raise RuntimeError("No ARM64 stereo patch sites found in this binary.")
    ok_n = warn_n = 0
    log.info("")
    for p in patches:
        fo = p["fat_offset"]
        orig = _hex_bytes(p["orig"])
        patch_b = _hex_bytes(p["patch"])
        if p.get("already_patched") or data[fo : fo + len(patch_b)] == patch_b:
            log.ok(f"  {p['name']}")
            ok_n += 1
        elif data[fo : fo + len(orig)] == orig:
            log.warn(f"  {p['name']} — still original bytes")
            warn_n += 1
        else:
            log.warn(f"  {p['name']} — unexpected bytes @ 0x{fo:X}")
            warn_n += 1
    log.info("")
    if warn_n == 0:
        log.ok(f"Verify passed: {ok_n}/{len(patches)} ARM64 site(s) patched")
    else:
        log.warn(f"Verify: {ok_n} OK, {warn_n} need attention ({len(patches)} total)")


def export_patched_node(node: Path, export_dir: Path, log: LogSink) -> Path:
    export_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(node, export_dir / "discord_voice.node")
    bd = backup_path_for(node)
    if bd.is_file():
        ob = export_dir / "original_backup"
        ob.mkdir(exist_ok=True)
        shutil.copy2(bd, ob / "discord_voice.node")
    (export_dir / "INSTALL_GUIDE.txt").write_text(
        "Discord Stereo Patcher — ARM64 export\n"
        "=====================================\n\n"
        "1. Quit Discord completely.\n"
        "2. Replace your discord_voice.node with the exported copy.\n"
        "3. Run: codesign --force --sign - discord_voice.node\n"
        "4. Reopen Discord and test stereo in a voice channel.\n",
        encoding="utf-8",
    )
    log.ok(f"Files exported to: {export_dir}")
    return export_dir


def diagnose_node(node: Path, log: "GuiLog") -> None:
    log.info(f"Path: {node}")
    if not node.is_file():
        raise RuntimeError("discord_voice.node does not exist.")
    st = node.stat()
    log.info(f"Size: {st.st_size:,} bytes ({st.st_size / (1024 * 1024):.2f} MB)")
    log.info(f"Discord build: v{_version_from_node(node)}")
    log.info(f"Patch state: {check_patch_status(str(node))}")
    bd = backup_path_for(node)
    log.info(f"Backup exists: {'yes' if bd.is_file() else 'no'} — {_short_home_path(bd)}")
    scan_patches(node, log)
    verify_patches(node, log)

class GuiLog:
    """Adapts PatcherApp._log to the patcher log interface."""

    def __init__(self, app: "PatcherApp") -> None:
        self._app = app

    def info(self, msg: str) -> None:
        self._app._log(msg)

    def ok(self, msg: str) -> None:
        self._app._log(f"  [OK] {msg}")

    def warn(self, msg: str) -> None:
        self._app._log(f"  [WARN] {msg}", "warn")

    def fail(self, msg: str) -> None:
        self._app._log(f"  [FAIL] {msg}", "error")


#   PatcherApp, run_gui

class PatcherApp:
    def __init__(self) -> None:
        if tk is None:
            raise RuntimeError(
                "tkinter is not available.\n"
                "macOS: install Python from python.org or use system python3 with tk support."
            )
        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.geometry("760x780")
        self.root.minsize(700, 700)
        self.root.configure(bg=COLORS["bg_dark"])

        self.discord_installations: List[Tuple[str, str]] = []
        # M9: display string -> absolute path. Avoids splitting the dropdown
        # value on " — " (which breaks if the user's home dir contains that
        # em-dash sequence).
        self._node_path_by_display: dict = {}
        self.selected_node = tk.StringVar(value="")
        self.is_running = False

        # M7: log file writer thread. Decouples disk I/O from the Tk main
        # thread so appending to the log never blocks UI redraws.
        self._log_queue: "queue.Queue[Optional[str]]" = queue.Queue()
        self._log_writer_thread = threading.Thread(
            target=self._log_writer_loop, name="PatcherLogWriter", daemon=True
        )
        self._log_writer_thread.start()

        self._build_ui()
        self.root.bind("<Map>", lambda _e: self.root.after_idle(self._repaint_rounded))
        self.root.after(50, self._repaint_rounded)
        self.root.after(200, self._repaint_rounded)
        self._scan_installations()

    def _log_writer_loop(self) -> None:
        """Drain self._log_queue and append each line to disk.

        Runs on a daemon thread so it never blocks Tk's main loop. A `None`
        sentinel signals shutdown.
        """
        while True:
            msg = self._log_queue.get()
            if msg is None:
                break
            try:
                with log_path().open("a", encoding="utf-8") as f:
                    f.write(msg + "\n")
            except Exception:
                pass
            finally:
                self._log_queue.task_done()

    def _repaint_rounded(self) -> None:
        self.root.update_idletasks()
        for widget in getattr(self, "_rounded_widgets", ()):
            paint = getattr(widget, "_paint", None)
            if callable(paint):
                paint()
        for btn in getattr(self, "_action_buttons", ()):
            if hasattr(btn, "_draw"):
                btn._draw()

    def _build_ui(self) -> None:
        main = tk.Frame(self.root, bg=COLORS["bg_dark"])
        main.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)

        tk.Label(
            main,
            text=APP_NAME,
            bg=COLORS["bg_dark"],
            fg=COLORS["text_header"],
            font=_ui_font_display(22),
            anchor=tk.W,
        ).pack(fill=tk.X)
        tk.Label(
            main,
            text=f"macOS ARM64  |  48 kHz  |  248 kbps  |  Stereo  |  Forced CELT  |  v{APP_VERSION}",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_muted"],
            font=_ui_font(10),
            anchor=tk.W,
        ).pack(fill=tk.X, pady=(4, 8))

        badges = tk.Frame(main, bg=COLORS["bg_dark"])
        badges.pack(fill=tk.X, pady=(0, 14))
        _badge(badges, "Apple Silicon (ARM64 only)", BADGE_GREEN_BG, BADGE_GREEN_FG).pack(side=tk.LEFT, padx=(0, 8))
        _badge(badges, "Stereo · 48 kHz · 248 kbps · CELT · Filterless", BADGE_GREEN_BG, BADGE_GREEN_FG).pack(side=tk.LEFT)

        install_card = SectionCard(main, "Discord Installation")
        install_card.pack(fill=tk.X, pady=(0, 10))
        sel_row = tk.Frame(install_card.body, bg=COLORS["bg_secondary"])
        sel_row.pack(fill=tk.X)
        self.install_picker = DarkDropdown(
            sel_row,
            self.selected_node,
            on_select=self._on_install_selected,
        )
        self.install_picker.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.btn_rescan = ThemedButton(
            sel_row,
            "Rescan",
            COLORS["bg_input"],
            COLORS["bg_tertiary"],
            self._scan_installations,
            fg=COLORS["text_normal"],
        )
        self.btn_rescan.pack(side=tk.LEFT)
        self.status_label = tk.Label(
            install_card.body,
            text="Scanning...",
            bg=COLORS["bg_secondary"],
            fg=COLORS["text_muted"],
            font=_ui_font(10),
            anchor=tk.W,
        )
        self.status_label.pack(fill=tk.X, pady=(8, 0))

        actions_card = SectionCard(main, "Actions")
        actions_card.pack(fill=tk.X, pady=(0, 10))
        btn_row = tk.Frame(actions_card.body, bg=COLORS["bg_secondary"])
        btn_row.pack(fill=tk.X)
        self.patch_btn = ThemedButton(
            btn_row,
            "Patch Discord",
            COLORS["blurple"],
            COLORS["blurple_dark"],
            self._start_patch,
        )
        self.patch_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.restore_btn = ThemedButton(
            btn_row,
            "Restore",
            COLORS["bg_input"],
            COLORS["bg_tertiary"],
            self._start_restore,
            fg=COLORS["text_normal"],
        )
        self.restore_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.verify_btn = ThemedButton(
            btn_row,
            "Verify",
            COLORS["bg_input"],
            COLORS["bg_tertiary"],
            self._start_verify,
            fg=COLORS["text_normal"],
        )
        self.verify_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.diagnose_btn = ThemedButton(
            btn_row,
            "Diagnose",
            COLORS["bg_input"],
            COLORS["bg_tertiary"],
            self._start_diagnose,
            fg=COLORS["text_normal"],
        )
        self.diagnose_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.export_btn = ThemedButton(
            btn_row,
            "Export",
            COLORS["bg_input"],
            COLORS["bg_tertiary"],
            self._start_export,
            fg=COLORS["text_normal"],
        )
        self.export_btn.pack(side=tk.LEFT)

        backup_row = tk.Frame(actions_card.body, bg=COLORS["bg_secondary"])
        backup_row.pack(fill=tk.X, pady=(12, 4))
        tk.Label(
            backup_row,
            text=f"Backups: {_short_home_path(BACKUP_DIR)}",
            bg=COLORS["bg_secondary"],
            fg=COLORS["text_muted"],
            font=_ui_font(10),
            anchor=tk.W,
        ).pack(side=tk.LEFT)
        self.btn_open_backups = ThemedButton(
            backup_row,
            "Open in Finder",
            COLORS["bg_input"],
            COLORS["bg_tertiary"],
            self._open_backups_folder,
            fg=COLORS["text_normal"],
        )
        self.btn_open_backups.pack(side=tk.RIGHT)

        import platform

        arch = platform.machine().lower()
        if arch == "arm64":
            sys1 = "Target: Apple Silicon discord_voice.node (ARM64 slice)"
            sys2 = "Intel/x86_64 slices are not modified by this patcher"
        else:
            sys1 = f"Host CPU: {arch} — patcher still targets the ARM64 slice inside the fat binary"
            sys2 = "Run on Apple Silicon or patch a copied discord_voice.node from Discord.app"
        tk.Label(
            actions_card.body,
            text=sys1,
            bg=COLORS["bg_secondary"],
            fg=COLORS["text_muted"],
            font=_ui_font(10),
            anchor=tk.W,
        ).pack(fill=tk.X, pady=(4, 0))
        tk.Label(
            actions_card.body,
            text=sys2,
            bg=COLORS["bg_secondary"],
            fg=COLORS["text_muted"],
            font=_ui_font(10),
            anchor=tk.W,
        ).pack(fill=tk.X, pady=(2, 0))

        self.progress = ProgressBar(actions_card.body)
        self.progress.pack(fill=tk.X, pady=(12, 6))
        self.progress_label = tk.Label(
            actions_card.body,
            text="Ready",
            bg=COLORS["bg_secondary"],
            fg=COLORS["text_muted"],
            font=_ui_font(10),
            anchor=tk.W,
        )
        self.progress_label.pack(fill=tk.X)

        log_card = SectionCard(main, "Log Output")
        log_card.pack(fill=tk.BOTH, expand=True)
        self.log_panel = RoundedLogPanel(log_card.body)
        self.log_panel.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        self.log_text = self.log_panel.text
        self.log_text.configure(state=tk.DISABLED)
        self.log_text.tag_configure("ok", foreground=COLORS["green"])
        self.log_text.tag_configure("error", foreground=COLORS["red"])
        self.log_text.tag_configure("warn", foreground=COLORS["yellow"])
        self.log_text.tag_configure("info", foreground=COLORS["text_muted"])
        self.log_text.tag_configure("header", foreground=COLORS["blurple"], font=(*_mono_font(10), "bold"))

        self._rounded_widgets = (install_card, actions_card, log_card, self.install_picker, self.log_panel)
        self._action_buttons = (
            self.btn_rescan,
            self.patch_btn,
            self.restore_btn,
            self.verify_btn,
            self.diagnose_btn,
            self.export_btn,
            self.btn_open_backups,
        )

    def _log(self, message: str, tag: Optional[str] = None) -> None:
        def _append() -> None:
            self.log_text.configure(state=tk.NORMAL)
            if tag:
                self.log_text.insert(tk.END, message + "\n", tag)
            elif "[OK]" in message:
                self.log_text.insert(tk.END, message + "\n", "ok")
            elif "[FAIL]" in message or "ERROR" in message:
                self.log_text.insert(tk.END, message + "\n", "error")
            elif "[WARN]" in message or "WARNING" in message:
                self.log_text.insert(tk.END, message + "\n", "warn")
            elif message.startswith("===") or message.startswith("---"):
                self.log_text.insert(tk.END, message + "\n", "header")
            else:
                self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)

        # Tk Text widget calls MUST happen on the main thread.
        self.root.after(0, _append)
        # M7: file-append I/O goes to the daemon writer thread via the queue,
        # so the Tk main loop never blocks on disk.
        self._log_queue.put(message)

    def _set_progress(self, current: int, total: int, label: str = "") -> None:
        pct = (current / total) * 100 if total > 0 else 0
        self.root.after(0, lambda: self.progress.set(pct))
        if label:
            self.root.after(0, lambda: self.progress_label.configure(text=label))

    def _set_buttons_state(self, enabled: bool) -> None:
        for btn in self._action_buttons:
            self.root.after(0, lambda b=btn, e=enabled: b.set_enabled(e))

    def _update_status(self, text: str) -> None:
        self.root.after(0, lambda: self.status_label.configure(text=text))

    def _clear_log(self) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _get_node_path(self, silent: bool = False) -> Optional[str]:
        val = self.selected_node.get()
        if not val:
            if not silent:
                messagebox.showwarning(
                    "No Installation",
                    "Please select a Discord installation first.",
                    parent=self.root,
                )
            return None
        # M9: dict lookup instead of splitting on " — " (which broke when the
        # user's home directory contained that em-dash sequence).
        path = self._node_path_by_display.get(val, val)
        if not os.path.isfile(path):
            if not silent:
                messagebox.showerror("File Not Found", f"Cannot find:\n{path}", parent=self.root)
            return None
        return path

    def _scan_installations(self) -> None:
        self.discord_installations = discover_discord_installations()
        values = [f"{name} — {path}" for name, path in self.discord_installations]
        # M9: keep the display->path mapping in sync with the dropdown values.
        self._node_path_by_display = {
            f"{name} — {path}": path for name, path in self.discord_installations
        }
        self.install_picker.set_values(values)
        if values:
            self.selected_node.set(values[0])
            self._on_install_selected()
        else:
            self.selected_node.set("")
            self._update_status("No Discord installations found")

    def _on_install_selected(self, event=None) -> None:
        path = self._get_node_path(silent=True)
        if path:
            self._update_status(format_node_status_line(path))
        else:
            self._update_status("No installation selected")

    def _open_backups_folder(self) -> None:
        # M5: BACKUP_DIR is the canonical root (app_data_dir() / "backups").
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        path = str(BACKUP_DIR)
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", path])
            elif sys.platform == "win32":
                os.startfile(path)  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open backups folder:\n{e}", parent=self.root)

    def _ask_launch_discord(self) -> None:
        try:
            if messagebox.askyesno("Patching Complete", "Launch Discord now?", parent=self.root):
                path = self._get_node_path(silent=True)
                if path:
                    relaunch_discord_for_node(Path(path), GuiLog(self))
        except Exception:
            pass

    def _start_patch(self) -> None:
        node_path = self._get_node_path()
        if not node_path:
            return

        # M3: verify the binary's identity (size + SHA-256) BEFORE starting the
        # worker thread. If it doesn't match, offer to download + install the
        # matching unpatched voice module from GitHub (mirrors the Windows
        # patcher's Save-VoiceBackupFiles + Invoke-PatchClients workflow).
        try:
            if not verify_node_identity(Path(node_path), GuiLog(self)):
                choice = messagebox.askyesno(
                    "Identity Check Failed",
                    "This discord_voice.node does not match the expected stock build\n"
                    "(file size or SHA-256 mismatch).\n\n"
                    "Discord may have auto-updated to a newer build.\n\n"
                    "Download the matching UNPATCHED voice module from GitHub and\n"
                    "REPLACE your current module folder? This will DOWNGRADE your\n"
                    "Discord voice module to the version the patcher supports.",
                    parent=self.root,
                )
                if not choice:
                    self._log("Patching aborted — identity check failed and user declined download.")
                    return
                # Run the download + install workflow on a worker thread so the
                # UI stays responsive (the download is ~85 MB total).
                self._clear_log()
                self._set_buttons_state(False)
                self._log("=== Voice Module Download & Install ===", "header")
                self._log("")

                def _do_download_and_install() -> None:
                    try:
                        log = GuiLog(self)
                        backup_dir = prepare_voice_backup(log)
                        if backup_dir is None:
                            self._log("\n  [FAIL] Voice backup download/verify failed.", "error")
                            self.root.after(0, lambda: self.progress_label.configure(text="Download failed"))
                            return
                        self._log("Closing Discord...")
                        try:
                            close_discord_for_node(Path(node_path), log)
                        except Exception as e:
                            self._log(f"\n  [FAIL] {e}", "error")
                            return
                        if not install_voice_module(Path(node_path), backup_dir, log):
                            self._log("\n  [FAIL] Voice module install failed.", "error")
                            self.root.after(0, lambda: self.progress_label.configure(text="Install failed"))
                            return
                        # Re-verify identity
                        if not verify_node_identity(Path(node_path), log):
                            self._log(
                                "\n  [FAIL] Installed node still does not match PATCHES_META.",
                                "error",
                            )
                            return
                        self._log("")
                        self._log("  [OK] Voice module installed successfully", "ok")
                        self._log("")
                        # Re-launch the normal patch flow on the main thread.
                        self.root.after(0, lambda: self._start_patch())
                    except Exception as e:
                        self._log(f"\n  [FAIL] Error: {e}", "error")
                        self.root.after(0, lambda: self.progress_label.configure(text="Error"))
                    finally:
                        self._set_buttons_state(True)

                threading.Thread(target=_do_download_and_install, daemon=True).start()
                return
        except Exception as e:
            messagebox.showerror(
                "Identity Check Error",
                f"Could not verify the binary:\n{e}",
                parent=self.root,
            )
            return

        try:
            status = check_patch_status(node_path)
        except Exception:
            status = "unknown"

        if status == "patched":
            if not messagebox.askyesno(
                "Already Patched",
                "This binary appears to already be patched.\nRe-apply patches?",
                parent=self.root,
            ):
                return
        elif status == "unknown":
            if not messagebox.askyesno(
                "Unknown Version",
                "This binary version could not be verified.\nOffsets may not match. Continue anyway?",
                parent=self.root,
            ):
                return
        elif status == "mismatch":
            if not messagebox.askyesno(
                "Mismatch Detected",
                "One or more patch sites have unexpected bytes (not original,\n"
                "not patched). Re-applying may overwrite unknown data.\n\n"
                "Continue anyway?",
                parent=self.root,
            ):
                return

        self._clear_log()
        self._set_buttons_state(False)

        def _do_patch() -> None:
            try:
                node = Path(node_path)
                log = GuiLog(self)
                self._log(f"=== Discord Stereo Patcher v{APP_VERSION} ===", "header")
                self._log("")

                self._log("Creating backup...")
                self._set_progress(1, 5)
                ensure_backup(node, log)

                self._log("Closing Discord...")
                self._set_progress(2, 5)
                close_discord_for_node(node, log)

                self._log("")
                self._set_progress(3, 5)
                try:
                    os.chmod(node_path, 0o644)
                except Exception:
                    pass

                data = bytearray(node.read_bytes())
                applied, skipped, names = apply_all_arm64_patches(data, arm64_only=True)
                if applied == 0 and skipped == 0:
                    raise RuntimeError("No ARM64 patches found (not a fat Mach-O or symbols missing).")

                self._set_progress(4, 5)
                if applied > 0:
                    _write_node_bytes(node, data, log)
                    record_last_patch(node)
                    # CRITICAL FIX 2 + M1 + M6: pass fallback_data + node + data
                    # so codesign can recover and coverage doesn't re-read.
                    codesign_node(node, log, fallback_data=bytes(data))
                    enable_library_validation_bypass(node, log)
                    _report_patch_coverage(node, log, applied=applied, data=bytes(data))
                else:
                    log.ok(f"Already patched ({skipped} site(s) verified)")
                    _report_patch_coverage(node, log, applied=0)

                self._set_progress(5, 5)
                self._log("")
                self._log("=== RESULTS ===", "header")
                if applied > 0:
                    self._log(f"  [OK] Applied {applied} ARM64 patch(es) (stereo + bitrate + filters)!")
                    for n in names:
                        if not n.endswith("(already)") and not n.endswith("(mismatch)"):
                            self._log(f"    - {n}")
                    self._log("")
                    self._log("Next steps:")
                    self._log("  1. Open Discord")
                    self._log("  2. Join a voice channel")
                    self._log("  3. Test stereo by hard-panning L/R in your DAW")
                    self.root.after(
                        0,
                        lambda: self.progress_label.configure(text=f"Complete! {applied} patches applied."),
                    )
                else:
                    self._log(f"  [OK] Already patched ({skipped} site(s) verified)")
                    self.root.after(0, lambda: self.progress_label.configure(text="Already patched"))

                self.root.after(100, self._ask_launch_discord)
            except Exception as e:
                self._log(f"\n  [FAIL] Error: {e}", "error")
                self.root.after(0, lambda: self.progress_label.configure(text="Error during patching"))
            finally:
                self._set_buttons_state(True)
                self.root.after(0, self._on_install_selected)

        threading.Thread(target=_do_patch, daemon=True).start()

    def _start_restore(self) -> None:
        node_path = self._get_node_path()
        if not node_path:
            return

        backups = list_backups()
        if not backups:
            messagebox.showinfo("No Backups", "No backup files found.", parent=self.root)
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Select Backup to Restore")
        dialog.geometry("550x350")
        dialog.configure(bg=COLORS["bg_dark"])
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(
            dialog,
            text="Select a backup to restore:",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_normal"],
            font=_ui_font(11),
        ).pack(padx=16, pady=(16, 8), anchor=tk.W)

        listbox = tk.Listbox(
            dialog,
            bg=COLORS["bg_secondary"],
            fg=COLORS["text_normal"],
            font=_mono_font(10),
            selectbackground=COLORS["blurple"],
            relief=tk.FLAT,
            borderwidth=0,
            highlightthickness=0,
        )
        listbox.pack(fill=tk.BOTH, expand=True, padx=16)

        for path, date, size in backups:
            listbox.insert(tk.END, f"  {date}  |  {size}  |  {os.path.basename(path)}")
        if backups:
            listbox.selection_set(0)

        def _do_restore() -> None:
            sel = listbox.curselection()
            if not sel:
                messagebox.showwarning("No Selection", "Please select a backup.", parent=dialog)
                return
            backup_path = backups[sel[0]][0]
            dialog.destroy()

            self._clear_log()
            self._set_buttons_state(False)

            def _restore_thread() -> None:
                try:
                    log = GuiLog(self)
                    self._log("=== Restoring from Backup ===", "header")
                    self._log(f"  Backup: {os.path.basename(backup_path)}")
                    self._log(f"  Target: {node_path}")
                    self._log("")
                    self._log("Closing Discord...")
                    close_discord_for_node(Path(node_path), log)
                    self._log("Restoring file...")
                    shutil.copy2(backup_path, node_path)
                    codesign_node(Path(node_path), log)
                    self._log("  [OK] Binary restored")
                    self._log("  [OK] Re-signed")
                    self._log("")
                    self._log("Restart Discord to use the original binary.")
                    self.root.after(0, lambda: self.progress_label.configure(text="Restore complete!"))
                except Exception as e:
                    self._log(f"\n  [FAIL] Error: {e}", "error")
                finally:
                    self._set_buttons_state(True)
                    self.root.after(0, self._on_install_selected)

            threading.Thread(target=_restore_thread, daemon=True).start()

        btn_frame = tk.Frame(dialog, bg=COLORS["bg_dark"])
        btn_frame.pack(fill=tk.X, padx=16, pady=12)
        ThemedButton(btn_frame, "Cancel", COLORS["bg_input"], COLORS["bg_tertiary"], dialog.destroy, fg=COLORS["text_normal"]).pack(
            side=tk.RIGHT, padx=(0, 8)
        )
        ThemedButton(btn_frame, "Restore", COLORS["blurple"], COLORS["blurple_dark"], _do_restore).pack(side=tk.RIGHT)

    def _start_diagnose(self) -> None:
        node_path = self._get_node_path()
        if not node_path:
            return
        self._clear_log()
        self._set_buttons_state(False)

        def _do_diagnose() -> None:
            try:
                self._log("=== Diagnose ===", "header")
                self._log("")
                diagnose_node(Path(node_path), GuiLog(self))
                self.root.after(0, lambda: self.progress_label.configure(text="Diagnose complete!"))
                self.root.after(0, lambda: self.progress.set(100))
            except Exception as e:
                self._log(f"\n  [FAIL] Error: {e}", "error")
            finally:
                self._set_buttons_state(True)

        threading.Thread(target=_do_diagnose, daemon=True).start()

    def _start_verify(self) -> None:
        node_path = self._get_node_path()
        if not node_path:
            return

        self._clear_log()
        self._set_buttons_state(False)

        def _do_verify() -> None:
            try:
                self._log("=== Verifying Patch Status ===", "header")
                self._log("")
                log = GuiLog(self)
                verify_patches(Path(node_path), log)
                self.root.after(0, lambda: self.progress_label.configure(text="Verify complete!"))
            except Exception as e:
                self._log(f"\n  [FAIL] Error: {e}", "error")
            finally:
                self._set_buttons_state(True)

        threading.Thread(target=_do_verify, daemon=True).start()

    def _start_export(self) -> None:
        node_path = self._get_node_path()
        if not node_path:
            return

        self.root.update_idletasks()
        export_dir = filedialog.askdirectory(
            parent=self.root,
            title="Select Export Directory",
            initialdir=str(Path.home() / "Desktop"),
        )
        if not export_dir:
            return

        export_dir = os.path.join(export_dir, "DiscordStereoPatch_export")
        self._clear_log()
        self._set_buttons_state(False)

        def _do_export() -> None:
            try:
                self._log("=== Exporting Patched Binary ===", "header")
                self._log(f"  Source: {node_path}")
                self._log(f"  Export: {export_dir}")
                self._log("")
                result = export_patched_node(Path(node_path), Path(export_dir), GuiLog(self))
                self._log("")
                self._log("=== Export Complete ===", "header")
                self._log(f"  [OK] Files exported to: {result}")
                self._log("  Contents:")
                self._log("    discord_voice.node      - Patched binary")
                self._log("    original_backup/        - Original binary")
                self._log("    INSTALL_GUIDE.txt       - Installation guide")
                self.root.after(0, lambda: self.progress_label.configure(text="Export complete!"))

                def _open_finder() -> None:
                    try:
                        subprocess.Popen(["open", str(result)])
                    except Exception:
                        pass

                self.root.after(100, _open_finder)
            except Exception as e:
                self._log(f"\n  [FAIL] Error: {e}", "error")
            finally:
                self._set_buttons_state(True)

        threading.Thread(target=_do_export, daemon=True).start()

    def run(self) -> None:
        self.root.mainloop()


def run_gui() -> int:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        safe_mkdir(app_data_dir())
    except Exception:
        pass
    try:
        PatcherApp().run()
        return 0
    except Exception as e:
        sys.stderr.write(f"{APP_NAME} failed: {human_exc(e)}\n")
        return 1



def _want_gui() -> bool:
    """M11: ONLY --gui / -g (and no args) trigger GUI mode.

    Everything else — including --help, --version, typos like `--secret`, and
    positional node paths — goes to CLI. The previous implementation routed
    any unknown flag to GUI mode, which made --help open a Tk window.
    """
    if len(sys.argv) < 2:
        return True
    arg = sys.argv[1]
    return arg in ("--gui", "-g", "/gui")


def main() -> int:
    if _want_gui():
        return run_gui()
    return run_cli(sys.argv[1:])



if __name__ == "__main__":
    raise SystemExit(main())

