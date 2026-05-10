import asyncio
import json
import re
import sys
import os
import shutil
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Callable

DOWNLOADS_DIR = Path(__file__).parent.parent / "downloads"
DOWNLOADS_DIR.mkdir(exist_ok=True)

_MODEL_CACHE = {}
_MODEL_CACHE_LOCK = threading.Lock()
_CUDA_DLLS_READY = False
_CUDA_DLLS_LOCK = threading.Lock()
_CUDA_DLL_HANDLES = []


def _safe_stem(name: str) -> str:
    stem = Path(name).stem
    # Allow Unicode letters/digits (including Hebrew) as well as common safe chars
    stem = re.sub(r"[^\w._\- ]", "_", stem, flags=re.UNICODE)
    stem = stem.strip("._ ")
    return stem or "transcript"


def _prepare_cuda_dlls(log_fn: Callable[[str], None]) -> None:
    """Ensure CUDA DLL directories are registered on Windows.
    Works with NVIDIA pip packages and local CUDA toolkit installs."""
    global _CUDA_DLLS_READY

    if os.name != "nt":
        _CUDA_DLLS_READY = True
        return

    with _CUDA_DLLS_LOCK:
        if _CUDA_DLLS_READY:
            return

        candidates: list[Path] = []

        # NVIDIA pip wheels layout
        py_base = Path(sys.executable).parent / "Lib" / "site-packages" / "nvidia"
        for rel in ("cublas/bin", "cudnn/bin", "cuda_nvrtc/bin", "cuda_runtime/bin"):
            candidates.append(py_base / rel)

        # Common CUDA Toolkit paths
        for ver in ("12.0", "12.1", "12.2", "12.3", "12.4", "12.5", "12.6", "12.8"):
            candidates.append(Path(rf"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v{ver}\bin"))

        added = 0
        path_additions: list[str] = []
        for path in candidates:
            try:
                if path.exists():
                    handle = os.add_dll_directory(str(path))
                    # Keep handle alive for process lifetime. If released, Windows
                    # can remove the directory from DLL resolution.
                    _CUDA_DLL_HANDLES.append(handle)
                    added += 1
                    path_additions.append(str(path))
            except Exception:
                # Ignore invalid/unavailable directories.
                pass

        if path_additions:
            # Some CTranslate2 runtime loads on Windows resolve via PATH.
            # Keep CUDA directories at the beginning so delayed runtime loads succeed.
            existing_path = os.environ.get("PATH", "")
            existing_norm = {p.strip().lower() for p in existing_path.split(os.pathsep) if p.strip()}
            prepend = [p for p in path_additions if p.strip().lower() not in existing_norm]
            if prepend:
                os.environ["PATH"] = os.pathsep.join(prepend + ([existing_path] if existing_path else []))
                log_fn(f"Prepended CUDA paths to PATH: {len(prepend)}")

        _CUDA_DLLS_READY = True
        if added:
            log_fn(f"Registered CUDA DLL directories: {added}")


def _srt_timestamp(seconds: float) -> str:
    ms = max(0, int(round(seconds * 1000)))
    h, rem = divmod(ms, 3_600_000)
    m, rem = divmod(rem, 60_000)
    s, rem = divmod(rem, 1_000)
    return f"{h:02d}:{m:02d}:{s:02d},{rem:03d}"


def _build_srt(segments: list[dict]) -> str:
    lines: list[str] = []
    for i, seg in enumerate(segments, start=1):
        lines.append(str(i))
        lines.append(f"{_srt_timestamp(seg['start'])} --> {_srt_timestamp(seg['end'])}")
        lines.append(seg["text"].strip())
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def _find_ffmpeg() -> str:
    found = shutil.which("ffmpeg")
    if found:
        return found

    try:
        import imageio_ffmpeg
        exe = imageio_ffmpeg.get_ffmpeg_exe()
        if exe and Path(exe).exists():
            return exe
    except Exception:
        pass

    for candidate in [
        r"C:\ffmpeg\bin\ffmpeg.exe",
        r"C:\Program Files\ffmpeg\bin\ffmpeg.exe",
        r"C:\Program Files (x86)\ffmpeg\bin\ffmpeg.exe",
    ]:
        if Path(candidate).exists():
            return candidate

    raise FileNotFoundError("ffmpeg not found. Run: pip install imageio-ffmpeg")


def _run_ffmpeg(cmd: list[str]) -> None:
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace")
        stdout = result.stdout.decode(errors="replace")
        detail = (stderr or stdout)[-2000:].strip()
        raise RuntimeError(f"ffmpeg failed (code {result.returncode}): {detail}")


def _extract_audio_for_whisper(input_path: Path, log_fn: Callable[[str], None]) -> Path:
    """Normalize source media into mono 16k WAV.
    This avoids timestamp/probing issues in malformed TS-like files."""
    ffmpeg = _find_ffmpeg()
    out_path = DOWNLOADS_DIR / f"_tmp_audio_{uuid.uuid4().hex}.wav"

    base = [
        ffmpeg, "-y",
        "-analyzeduration", "200M",
        "-probesize", "200M",
        "-fflags", "+genpts+igndts",
        "-i", str(input_path),
    ]

    primary = base + [
        "-map", "0:a:0",
        "-vn",
        "-ac", "1",
        "-ar", "16000",
        "-c:a", "pcm_s16le",
        str(out_path),
    ]
    fallback = base + [
        "-vn",
        "-ac", "1",
        "-ar", "16000",
        "-c:a", "pcm_s16le",
        str(out_path),
    ]

    log_fn("Normalizing media with ffmpeg (audio 16k mono WAV)...")
    try:
        _run_ffmpeg(primary)
    except Exception:
        # Some files expose unusual stream maps, fallback to automatic audio selection.
        _run_ffmpeg(fallback)

    if not out_path.exists():
        raise RuntimeError("Failed to extract audio for transcription")

    size_mb = round(out_path.stat().st_size / (1024 * 1024), 1)
    log_fn(f"Prepared audio: {out_path.name} ({size_mb} MB)")
    return out_path


def _get_model(model_size: str, log_fn: Callable[[str], None]):
    _prepare_cuda_dlls(log_fn)

    try:
        from faster_whisper import WhisperModel
    except Exception as exc:
        raise RuntimeError(
            "faster-whisper לא מותקן בסביבת Python של השרת.\n"
            f"Python: {sys.executable}\n"
            f"הרצה מומלצת: \"{sys.executable}\" -m pip install faster-whisper"
        ) from exc

    attempts = [
        ("auto", "auto"),
        ("cuda", "float16"),
        ("cuda", "int8_float16"),
        ("cpu", "int8"),
        ("cpu", "float32"),
    ]

    errors: list[str] = []
    for device, compute_type in attempts:
        cache_key = (model_size, device, compute_type)
        with _MODEL_CACHE_LOCK:
            cached = _MODEL_CACHE.get(cache_key)
        if cached is not None:
            return cached, device, compute_type

        try:
            log_fn(f"Loading model '{model_size}' ({device}/{compute_type})...")
            model = WhisperModel(model_size, device=device, compute_type=compute_type)
            with _MODEL_CACHE_LOCK:
                _MODEL_CACHE[cache_key] = model
            return model, device, compute_type
        except Exception as exc:
            errors.append(f"{device}/{compute_type}: {exc}")

    raise RuntimeError("לא הצלחתי לטעון את המודל. " + " | ".join(errors[-3:]))


def _is_cuda_runtime_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return (
        "cublas64_12.dll" in msg
        or "cudnn64_9.dll" in msg
        or "cudnn_ops64_9.dll" in msg
        or "cuda" in msg and "cannot be loaded" in msg
    )


def _transcribe_sync(
    input_path: Path,
    model_size: str,
    language: str,
    task: str,
    word_timestamps: bool,
    log_fn: Callable[[str], None],
    progress_fn: Callable[[float], None] | None = None,
    output_dir: Path | None = None,
    output_stem: str | None = None,
) -> dict:
    prepared_audio_path: Path | None = None
    try:
        model, used_device, used_compute = _get_model(model_size, log_fn)

        safe_language = (language or "auto").strip().lower()
        language_arg = None if safe_language in {"", "auto"} else safe_language
        safe_task = "translate" if (task or "").strip().lower() == "translate" else "transcribe"

        prepared_audio_path = _extract_audio_for_whisper(input_path, log_fn)

        log_fn("Starting transcription...")
        if progress_fn:
            # Show immediate movement so long first decode step is not perceived as stuck.
            progress_fn(0.2)

        beam_size = 5 if used_device != "cpu" else 2

        def _run_and_collect(selected_model):
            segments_gen, info = selected_model.transcribe(
                str(prepared_audio_path or input_path),
                language=language_arg,
                task=safe_task,
                beam_size=beam_size,
                vad_filter=True,
                chunk_length=20,
                word_timestamps=bool(word_timestamps),
            )

            segments: list[dict] = []
            text_lines: list[str] = []
            total_duration = float(
                getattr(info, "duration_after_vad", 0) or getattr(info, "duration", 0) or 0
            )
            last_pct = -1.0

            for idx, seg in enumerate(segments_gen, start=1):
                text = (seg.text or "").strip()
                text_lines.append(text)

                item = {
                    "id": idx,
                    "start": float(seg.start),
                    "end": float(seg.end),
                    "text": text,
                }

                if word_timestamps and getattr(seg, "words", None):
                    item["words"] = [
                        {
                            "start": float(w.start),
                            "end": float(w.end),
                            "word": (w.word or "").strip(),
                            "probability": float(getattr(w, "probability", 0.0)),
                        }
                        for w in seg.words
                    ]

                segments.append(item)

                if progress_fn and total_duration > 0:
                    pct = max(0.0, min(100.0, (float(seg.end) / total_duration) * 100.0))
                    # avoid noisy tiny updates
                    if pct - last_pct >= 1.0 or pct >= 100.0:
                        last_pct = pct
                        progress_fn(pct)

                if idx == 1 or idx % 20 == 0:
                    log_fn(f"Transcribed {idx} segments...")

            return info, segments, text_lines

        try:
            info, segments, text_lines = _run_and_collect(model)
        except Exception as exc:
            # Some Windows setups fail only when CUDA kernels are first executed
            # (often during segment iteration, not necessarily on transcribe() call).
            if used_device != "cpu" and _is_cuda_runtime_error(exc):
                log_fn("CUDA runtime error detected. Falling back to CPU...")
                log_fn("CPU mode is slower; progress may advance in larger jumps.")
                if progress_fn:
                    progress_fn(0.5)
                cpu_key = (model_size, "cpu", "int8")
                with _MODEL_CACHE_LOCK:
                    cpu_model = _MODEL_CACHE.get(cpu_key)
                if cpu_model is None:
                    from faster_whisper import WhisperModel
                    cpu_model = WhisperModel(model_size, device="cpu", compute_type="int8")
                    with _MODEL_CACHE_LOCK:
                        _MODEL_CACHE[cpu_key] = cpu_model
                model = cpu_model
                used_device = "cpu"
                used_compute = "int8"
                beam_size = 2
                info, segments, text_lines = _run_and_collect(model)
            else:
                raise

        if progress_fn:
            progress_fn(100.0)

        base = _safe_stem(output_stem) if output_stem else _safe_stem(input_path.name.replace("_tmp_", ""))
        out_dir = output_dir if output_dir is not None else DOWNLOADS_DIR
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        txt_path = out_dir / f"{base}_transcript.txt"
        srt_path = out_dir / f"{base}_transcript.srt"
        json_path = out_dir / f"{base}_transcript.json"

        full_text = "\n".join(line for line in text_lines if line).strip() + "\n"
        txt_path.write_text(full_text, encoding="utf-8")
        srt_path.write_text(_build_srt(segments), encoding="utf-8")

        json_payload = {
            "model": model_size,
            "device": used_device,
            "compute_type": used_compute,
            "task": safe_task,
            "language_requested": safe_language,
            "language_detected": getattr(info, "language", None),
            "language_probability": getattr(info, "language_probability", None),
            "duration_sec": getattr(info, "duration", None),
            "duration_after_vad_sec": getattr(info, "duration_after_vad", None),
            "segments_count": len(segments),
            "segments": segments,
            "text": full_text,
        }
        json_path.write_text(json.dumps(json_payload, ensure_ascii=False, indent=2), encoding="utf-8")

        return {
            "filename": txt_path.name,
            "txt_filename": txt_path.name,
            "srt_filename": srt_path.name,
            "json_filename": json_path.name,
            "segments_count": len(segments),
            "language": getattr(info, "language", None),
            "language_probability": getattr(info, "language_probability", None),
            "duration_sec": getattr(info, "duration", None),
            "duration_after_vad_sec": getattr(info, "duration_after_vad", None),
            "model": model_size,
            "device": used_device,
            "compute_type": used_compute,
            "task": safe_task,
            "size_mb": round(txt_path.stat().st_size / (1024 * 1024), 3),
        }
    finally:
        if prepared_audio_path and prepared_audio_path.exists():
            try:
                prepared_audio_path.unlink(missing_ok=True)
            except Exception:
                pass


async def transcribe_media_file(
    input_path: Path,
    log_fn: Callable[[str], None],
    model_size: str = "large-v3",
    language: str = "he",
    task: str = "transcribe",
    word_timestamps: bool = False,
    progress_fn: Callable[[float], None] | None = None,
    output_dir: Path | None = None,
    output_stem: str | None = None,
) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        _transcribe_sync,
        input_path,
        model_size,
        language,
        task,
        word_timestamps,
        log_fn,
        progress_fn,
        output_dir,
        output_stem,
    )
