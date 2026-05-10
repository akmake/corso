import asyncio
from pathlib import Path

DOWNLOADS_DIR = Path(__file__).parent.parent / "downloads"
DOWNLOADS_DIR.mkdir(exist_ok=True)


def _ydl_opts(output_template: str, format_str: str, headers: dict, log_fn) -> dict:
    opts = {
        "outtmpl": output_template,
        "noplaylist": True,
        "quiet": True,
        "no_warnings": True,
        "progress_hooks": [_make_hook(log_fn)],
    }

    if format_str == "audio_only":
        opts["format"] = "bestaudio/best"
        opts["postprocessors"] = [{
            "key": "FFmpegExtractAudio",
            "preferredcodec": "mp3",
            "preferredquality": "0",
        }]
    else:
        opts["format"] = format_str
        opts["merge_output_format"] = "mp4"

    if headers:
        opts["http_headers"] = headers

    return opts


def _make_hook(log_fn):
    def hook(d):
        if d["status"] == "downloading":
            pct   = d.get("_percent_str", "").strip()
            speed = d.get("_speed_str", "").strip()
            eta   = d.get("eta", "")
            total = d.get("_total_bytes_str") or d.get("_total_bytes_estimate_str", "")
            parts = filter(None, [pct, f"of {total}" if total else None,
                                  f"at {speed}" if speed else None,
                                  f"ETA {eta}s" if eta else None])
            log_fn(f"[download] {' '.join(parts)}")
        elif d["status"] == "finished":
            log_fn(f"[download] הושלם: {Path(d['filename']).name}")
    return hook


async def get_video_info(url: str, headers: dict = None) -> dict:
    from yt_dlp import YoutubeDL

    opts = {
        "quiet": True, "no_warnings": True, "noplaylist": True,
        "skip_download": True,
    }
    if headers:
        opts["http_headers"] = headers

    loop = asyncio.get_event_loop()

    def _extract():
        with YoutubeDL(opts) as ydl:
            return ydl.extract_info(url, download=False)

    try:
        info = await asyncio.wait_for(loop.run_in_executor(None, _extract), timeout=30)
    except asyncio.TimeoutError:
        return {"error": "פג זמן הבקשה — בדוק את הURL"}
    except Exception as e:
        return {"error": str(e)}

    if not info:
        return {"error": "לא ניתן לאחזר מידע על הסרטון"}

    # Build format list
    formats = [{"label": "הטוב ביותר (אוטומטי)", "value": "best", "height": 9999}]
    seen = set()
    for f in reversed(info.get("formats", [])):
        h = f.get("height")
        if f.get("vcodec", "none") != "none" and h and h not in seen:
            seen.add(h)
            formats.append({
                "label": f"{h}p",
                "value": f"bestvideo[height<={h}]+bestaudio/best[height<={h}]/best",
                "height": h,
            })
    formats.sort(key=lambda x: x["height"], reverse=True)
    formats.append({"label": "שמע בלבד (MP3)", "value": "audio_only", "height": 0})

    duration = int(info.get("duration") or 0)
    h, r = divmod(duration, 3600)
    m, s = divmod(r, 60)
    dur_str = f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

    return {
        "title":      info.get("title", ""),
        "uploader":   info.get("uploader") or info.get("channel", ""),
        "duration":   dur_str,
        "thumbnail":  info.get("thumbnail", ""),
        "view_count": info.get("view_count"),
        "formats":    formats,
    }


async def download_video(url: str, format_str: str, job_id: str, log_fn,
                          headers: dict = None) -> dict:
    from yt_dlp import YoutubeDL

    output_template = str(DOWNLOADS_DIR / f"{job_id}.%(ext)s")
    opts = _ydl_opts(output_template, format_str, headers or {}, log_fn)

    log_fn(f"מוריד: {url}")
    log_fn(f"פורמט: {'שמע MP3' if format_str == 'audio_only' else format_str}")

    loop = asyncio.get_event_loop()

    def _download():
        with YoutubeDL(opts) as ydl:
            ydl.download([url])

    try:
        await loop.run_in_executor(None, _download)
    except Exception as e:
        return {"error": str(e)}

    for f in DOWNLOADS_DIR.iterdir():
        if f.stem == job_id:
            size_mb = round(f.stat().st_size / (1024 * 1024), 1)
            return {"filename": f.name, "size_mb": size_mb}

    return {"error": "הקובץ לא נמצא לאחר ההורדה"}
