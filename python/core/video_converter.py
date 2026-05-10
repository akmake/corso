import asyncio
import shutil
import subprocess
from pathlib import Path

DOWNLOADS_DIR = Path(__file__).parent.parent / "downloads"
DOWNLOADS_DIR.mkdir(exist_ok=True)


def _find_ffmpeg() -> str:
    """Locate the ffmpeg binary.
    Search order: system PATH -> imageio-ffmpeg bundle -> yt-dlp dir -> common paths."""

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

    try:
        import yt_dlp
        base = Path(yt_dlp.__file__).parent
        for name in ("ffmpeg.exe", "ffmpeg"):
            candidate = base / name
            if candidate.exists():
                return str(candidate)
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
    """Run an ffmpeg command synchronously and raise on failure."""
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace")
        stdout = result.stdout.decode(errors="replace")
        detail = (stderr or stdout)[-800:].strip()
        raise RuntimeError(f"ffmpeg failed (code {result.returncode}): {detail}")


async def convert_mp4_to_mp3(input_path: Path, log_fn) -> dict:
    """Convert any video file to MP3 using ffmpeg."""
    output_name = input_path.stem + ".mp3"
    output_path = DOWNLOADS_DIR / output_name

    log_fn(f"Converting {input_path.name} to MP3...")

    try:
        ffmpeg = _find_ffmpeg()
        log_fn(f"ffmpeg: {ffmpeg}")
    except FileNotFoundError as exc:
        raise RuntimeError(str(exc)) from exc

    cmd = [
        ffmpeg, "-y",
        "-i", str(input_path),
        "-vn",
        "-acodec", "libmp3lame",
        "-q:a", "2",
        str(output_path),
    ]

    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, _run_ffmpeg, cmd)
    except Exception as exc:
        raise RuntimeError(str(exc)) from exc

    if not output_path.exists():
        raise RuntimeError("Output file was not created")

    size_mb = round(output_path.stat().st_size / (1024 * 1024), 1)
    log_fn(f"Done: {output_name} ({size_mb} MB)")
    return {"filename": output_name, "size_mb": size_mb}


async def keep_audio_mp4(input_path: Path, log_fn) -> dict:
    """Create an MP4 file that keeps only audio (no video stream)."""
    output_name = input_path.stem + "_audio_only.mp4"
    output_path = DOWNLOADS_DIR / output_name

    log_fn(f"Removing video track and keeping audio only from {input_path.name}...")

    try:
        ffmpeg = _find_ffmpeg()
        log_fn(f"ffmpeg: {ffmpeg}")
    except FileNotFoundError as exc:
        raise RuntimeError(str(exc)) from exc

    cmd_copy = [
        ffmpeg, "-y",
        "-i", str(input_path),
        "-vn",
        "-c:a", "copy",
        str(output_path),
    ]

    cmd_aac = [
        ffmpeg, "-y",
        "-i", str(input_path),
        "-vn",
        "-c:a", "aac",
        "-b:a", "192k",
        str(output_path),
    ]

    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, _run_ffmpeg, cmd_copy)
    except Exception:
        log_fn("Audio stream copy failed, retrying with AAC re-encode...")
        try:
            await loop.run_in_executor(None, _run_ffmpeg, cmd_aac)
        except Exception as exc:
            raise RuntimeError(str(exc)) from exc

    if not output_path.exists():
        raise RuntimeError("Output file was not created")

    size_mb = round(output_path.stat().st_size / (1024 * 1024), 1)
    log_fn(f"Done: {output_name} ({size_mb} MB)")
    return {"filename": output_name, "size_mb": size_mb}