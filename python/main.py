import asyncio
import json
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import (
    BackgroundTasks,
    FastAPI,
    File,
    Form,
    HTTPException,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from core.audio_transcriber import transcribe_media_file
from core.courses_manager import db as _cdb

app = FastAPI(
    title="WEBINT Courses API",
    description="Course-focused backend with lesson download, transcription, and presentations.",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str) -> None:
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass


manager = ConnectionManager()
jobs: Dict[str, Dict[str, Any]] = {}


def log(job_id: str, msg: str) -> None:
    if job_id not in jobs:
        return
    jobs[job_id]["progress"].append(msg)
    try:
        loop = asyncio.get_running_loop()
        message = json.dumps(
            {"job_id": job_id, "msg": msg, "status": jobs[job_id]["status"]},
            ensure_ascii=False,
        )
        loop.create_task(manager.broadcast(message))
    except RuntimeError:
        pass


@app.websocket("/ws/jobs")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/api/v1/jobs/{job_id}")
async def get_job(job_id: str):
    if job_id not in jobs:
        return {"status": "not_found", "result": {"error": "Job not found"}}
    return jobs[job_id]


@app.on_event("startup")
async def clear_stale_job_ids():
    """Clear job IDs that point to old in-memory jobs after a restart."""
    for course in _cdb.list_courses():
        for lesson_id, lesson in (course.get("lessons") or {}).items():
            updates = {}
            if lesson.get("transcript_job_id"):
                updates["transcript_job_id"] = None
            if lesson.get("download_job_id"):
                updates["download_job_id"] = None
            if updates:
                _cdb.update_lesson(course["id"], lesson_id, **updates)


class CreateCourseRequest(BaseModel):
    name: str


class AddLessonRequest(BaseModel):
    title: str
    url: str
    format: str = "best"
    headers: Optional[Dict[str, str]] = None


class ImportLessonRequest(BaseModel):
    title: str
    path: str


class TranscribeLessonRequest(BaseModel):
    model_size: str = "large-v3"
    language: str = "he"
    task: str = "transcribe"
    word_timestamps: bool = False


class ImportPresentationRequest(BaseModel):
    path: str


ALLOWED_MEDIA_EXTS = {
    ".mp4",
    ".mkv",
    ".avi",
    ".mov",
    ".webm",
    ".m4v",
    ".mp3",
    ".m4a",
    ".wav",
    ".ogg",
    ".flac",
}
ALLOWED_PRESENTATION_EXTS = {".pdf", ".pptx", ".ppt", ".odp", ".key"}


@app.get("/api/v1/courses")
async def list_courses():
    return {"courses": _cdb.list_courses()}


@app.post("/api/v1/courses")
async def create_course(req: CreateCourseRequest):
    return _cdb.create_course(req.name)


@app.delete("/api/v1/courses/{course_id}")
async def delete_course(course_id: str):
    if not _cdb.get_course(course_id):
        raise HTTPException(status_code=404, detail="Course not found")
    _cdb.delete_course(course_id)
    return {"ok": True}


@app.post("/api/v1/courses/{course_id}/lessons/import")
async def import_lesson(course_id: str, req: ImportLessonRequest):
    if not _cdb.get_course(course_id):
        raise HTTPException(status_code=404, detail="Course not found")

    raw = req.path.strip().strip('"').strip("'")
    src = Path(raw)
    if not src.exists() or not src.is_file():
        raise HTTPException(status_code=400, detail=f"File not found: {src}")
    if src.suffix.lower() not in ALLOWED_MEDIA_EXTS:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {src.suffix}")

    loop = asyncio.get_event_loop()
    lesson = await loop.run_in_executor(None, _cdb.add_lesson_file, course_id, req.title.strip(), src)
    return {"lesson": lesson}


async def _run_lesson_download(
    job_id: str,
    course_id: str,
    lesson_id: str,
    url: str,
    format_str: str,
    headers: dict,
):
    try:
        from yt_dlp import YoutubeDL

        lesson_dir = _cdb.lesson_dir(course_id, lesson_id)
        output_template = str(lesson_dir / "video.%(ext)s")
        opts = {
            "outtmpl": output_template,
            "noplaylist": True,
            "quiet": True,
            "no_warnings": True,
        }
        if format_str == "audio_only":
            opts["format"] = "bestaudio/best"
            opts["postprocessors"] = [
                {
                    "key": "FFmpegExtractAudio",
                    "preferredcodec": "mp3",
                    "preferredquality": "0",
                }
            ]
        else:
            opts["format"] = format_str
            opts["merge_output_format"] = "mp4"
        if headers:
            opts["http_headers"] = headers

        def _hook(d):
            if d["status"] == "downloading":
                pct = d.get("_percent_str", "").strip()
                speed = d.get("_speed_str", "").strip()
                eta = d.get("eta", "")
                parts = filter(None, [pct, f"at {speed}" if speed else None, f"ETA {eta}s" if eta else None])
                log(job_id, f"[download] {' '.join(parts)}")
            elif d["status"] == "finished":
                log(job_id, f"[download] completed: {Path(d['filename']).name}")

        opts["progress_hooks"] = [_hook]
        log(job_id, f"Downloading: {url}")

        def _download():
            with YoutubeDL(opts) as ydl:
                ydl.download([url])

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _download)

        video_file = next((f for f in lesson_dir.iterdir() if f.is_file() and f.stem == "video"), None)
        if not video_file:
            raise RuntimeError("Downloaded file not found")

        size_mb = round(video_file.stat().st_size / (1024 * 1024), 1)
        current = _cdb.get_lesson(course_id, lesson_id)
        if current and current.get("download_job_id") == job_id:
            _cdb.update_lesson(
                course_id,
                lesson_id,
                video_filename=video_file.name,
                video_size_mb=size_mb,
                download_job_id=None,
                download_error=None,
            )

        jobs[job_id]["status"] = "completed"
        jobs[job_id]["result"] = {"filename": video_file.name, "size_mb": size_mb}
        log(job_id, f"Download completed: {video_file.name} ({size_mb} MB)")
    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["result"] = {"error": str(e)}
        log(job_id, f"Error: {e}")
        current = _cdb.get_lesson(course_id, lesson_id)
        if current and current.get("download_job_id") == job_id:
            _cdb.update_lesson(course_id, lesson_id, download_job_id=None, download_error=str(e))


@app.post("/api/v1/courses/{course_id}/lessons")
async def add_lesson(course_id: str, req: AddLessonRequest, background_tasks: BackgroundTasks):
    if not _cdb.get_course(course_id):
        raise HTTPException(status_code=404, detail="Course not found")

    raw = req.url.strip().strip('"').strip("'")
    src = Path(raw)
    title = req.title.strip() or src.stem or "Lesson"

    if src.exists() and src.is_file():
        loop = asyncio.get_event_loop()
        lesson = await loop.run_in_executor(None, _cdb.add_lesson_file, course_id, title, src)
        return {"lesson": lesson, "job_id": None}

    job_id = str(uuid.uuid4())
    lesson = _cdb.add_lesson_url(course_id, title, req.url, job_id)
    jobs[job_id] = {"status": "running", "type": "lesson_download", "result": None, "progress": []}
    background_tasks.add_task(
        _run_lesson_download,
        job_id,
        course_id,
        lesson["id"],
        req.url,
        req.format,
        req.headers or {},
    )
    return {"lesson": lesson, "job_id": job_id}


@app.delete("/api/v1/courses/{course_id}/lessons/{lesson_id}")
async def delete_lesson(course_id: str, lesson_id: str):
    if not _cdb.get_course(course_id):
        raise HTTPException(status_code=404, detail="Course not found")
    if not _cdb.get_lesson(course_id, lesson_id):
        raise HTTPException(status_code=404, detail="Lesson not found")
    _cdb.delete_lesson(course_id, lesson_id)
    return {"ok": True}


async def _run_lesson_transcribe(
    job_id: str,
    course_id: str,
    lesson_id: str,
    video_path: Path,
    model_size: str,
    language: str,
    task: str,
    word_timestamps: bool,
):
    try:
        def _progress(pct: float):
            value = round(float(pct), 1)
            if value >= 100.0 and jobs.get(job_id, {}).get("status") == "running":
                value = 99.5
            jobs[job_id]["percent"] = value

        lesson_dir = _cdb.lesson_dir(course_id, lesson_id)
        result = await transcribe_media_file(
            input_path=video_path,
            log_fn=lambda msg: log(job_id, msg),
            model_size=model_size,
            language=language,
            task=task,
            word_timestamps=word_timestamps,
            progress_fn=_progress,
            output_dir=lesson_dir,
            output_stem=lesson_dir.name,
        )

        current = _cdb.get_lesson(course_id, lesson_id)
        if current and current.get("transcript_job_id") == job_id:
            _cdb.update_lesson(
                course_id,
                lesson_id,
                transcript_txt=result.get("txt_filename"),
                transcript_srt=result.get("srt_filename"),
                transcript_job_id=None,
            )

        jobs[job_id]["status"] = "completed"
        jobs[job_id]["percent"] = 100.0
        jobs[job_id]["result"] = result
    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["result"] = {"error": str(e)}
        log(job_id, f"Error: {e}")
        current = _cdb.get_lesson(course_id, lesson_id)
        if current and current.get("transcript_job_id") == job_id:
            _cdb.update_lesson(course_id, lesson_id, transcript_job_id=None)


@app.post("/api/v1/courses/{course_id}/lessons/{lesson_id}/transcribe")
async def transcribe_lesson(
    course_id: str,
    lesson_id: str,
    req: TranscribeLessonRequest,
    background_tasks: BackgroundTasks,
):
    lesson = _cdb.get_lesson(course_id, lesson_id)
    if not lesson:
        raise HTTPException(status_code=404, detail="Lesson not found")
    if not lesson.get("video_filename"):
        raise HTTPException(status_code=400, detail="Lesson has no video yet")

    video_path = _cdb.lesson_dir(course_id, lesson_id) / lesson["video_filename"]
    if not video_path.exists():
        raise HTTPException(status_code=404, detail="Video file not found")

    old_job_id = lesson.get("transcript_job_id")
    if old_job_id and old_job_id in jobs:
        jobs[old_job_id]["status"] = "cancelled"

    job_id = str(uuid.uuid4())
    _cdb.update_lesson(course_id, lesson_id, transcript_job_id=job_id)
    jobs[job_id] = {"status": "running", "type": "lesson_transcribe", "result": None, "progress": [], "percent": 0.0}
    background_tasks.add_task(
        _run_lesson_transcribe,
        job_id,
        course_id,
        lesson_id,
        video_path,
        req.model_size,
        req.language,
        req.task,
        req.word_timestamps,
    )
    return {"job_id": job_id}


@app.get("/api/v1/courses/{course_id}/lessons/{lesson_id}/video")
async def serve_lesson_video(course_id: str, lesson_id: str):
    lesson = _cdb.get_lesson(course_id, lesson_id)
    if not lesson or not lesson.get("video_filename"):
        raise HTTPException(status_code=404, detail="Video not found")

    file_path = _cdb.lesson_dir(course_id, lesson_id) / lesson["video_filename"]
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Video file missing")

    return FileResponse(str(file_path), filename=lesson["video_filename"], media_type="application/octet-stream")


@app.get("/api/v1/courses/{course_id}/lessons/{lesson_id}/transcript/{fmt}")
async def serve_lesson_transcript(course_id: str, lesson_id: str, fmt: str):
    lesson = _cdb.get_lesson(course_id, lesson_id)
    if not lesson:
        raise HTTPException(status_code=404, detail="Lesson not found")

    key = "transcript_txt" if fmt == "txt" else "transcript_srt"
    filename = lesson.get(key)
    if not filename:
        raise HTTPException(status_code=404, detail="Transcript not available")

    file_path = _cdb.lesson_dir(course_id, lesson_id) / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Transcript file missing")

    return FileResponse(str(file_path), filename=filename, media_type="text/plain; charset=utf-8")


@app.post("/api/v1/courses/{course_id}/lessons/upload")
async def upload_lesson_video(course_id: str, title: str = Form(""), file: UploadFile = File(...)):
    if not _cdb.get_course(course_id):
        raise HTTPException(status_code=404, detail="Course not found")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in ALLOWED_MEDIA_EXTS:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {suffix}")

    lesson_title = title.strip() or Path(file.filename).stem
    content = await file.read()
    loop = asyncio.get_event_loop()
    lesson = await loop.run_in_executor(None, _cdb.add_lesson_file_bytes, course_id, lesson_title, file.filename, content)
    return {"lesson": lesson}


@app.post("/api/v1/courses/{course_id}/lessons/{lesson_id}/presentations/upload")
async def upload_presentation(course_id: str, lesson_id: str, file: UploadFile = File(...)):
    if not _cdb.get_lesson(course_id, lesson_id):
        raise HTTPException(status_code=404, detail="Lesson not found")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in ALLOWED_PRESENTATION_EXTS:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {suffix}")

    content = await file.read()
    loop = asyncio.get_event_loop()
    filename = await loop.run_in_executor(None, _cdb.add_presentation_bytes, course_id, lesson_id, file.filename, content)
    return {"filename": filename}


@app.post("/api/v1/courses/{course_id}/lessons/{lesson_id}/presentations/import")
async def import_presentation(course_id: str, lesson_id: str, req: ImportPresentationRequest):
    if not _cdb.get_lesson(course_id, lesson_id):
        raise HTTPException(status_code=404, detail="Lesson not found")

    raw = req.path.strip().strip('"').strip("'")
    src = Path(raw)
    if not src.exists() or not src.is_file():
        raise HTTPException(status_code=400, detail=f"File not found: {src}")

    suffix = src.suffix.lower()
    if suffix not in ALLOWED_PRESENTATION_EXTS:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {suffix}")

    loop = asyncio.get_event_loop()
    filename = await loop.run_in_executor(None, _cdb.add_presentation, course_id, lesson_id, src)
    return {"filename": filename}


@app.delete("/api/v1/courses/{course_id}/lessons/{lesson_id}/presentations/{filename}")
async def delete_presentation(course_id: str, lesson_id: str, filename: str):
    if not _cdb.get_lesson(course_id, lesson_id):
        raise HTTPException(status_code=404, detail="Lesson not found")

    _cdb.delete_presentation(course_id, lesson_id, filename)
    return {"ok": True}


@app.get("/api/v1/courses/{course_id}/lessons/{lesson_id}/presentations/{filename}")
async def serve_presentation(course_id: str, lesson_id: str, filename: str):
    lesson = _cdb.get_lesson(course_id, lesson_id)
    if not lesson:
        raise HTTPException(status_code=404, detail="Lesson not found")

    file_path = _cdb.lesson_dir(course_id, lesson_id) / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Presentation file missing")

    return FileResponse(str(file_path))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
