import json
import re
import shutil
import uuid
from datetime import datetime
from pathlib import Path

_BASE = Path(__file__).parent.parent
COURSES_DIR = _BASE / "courses_data"
COURSES_FILE = _BASE / "courses.json"
COURSES_DIR.mkdir(exist_ok=True)


def _safe(name: str) -> str:
    safe = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name.strip())
    return safe.strip('. ') or "unnamed"


def _unique_path(parent: Path, base: str) -> Path:
    candidate = parent / base
    if not candidate.exists():
        return candidate
    i = 2
    while (parent / f"{base}_{i}").exists():
        i += 1
    return parent / f"{base}_{i}"


class CoursesDB:
    def __init__(self):
        self._data: dict = {}
        self._reload()

    def _reload(self):
        try:
            if COURSES_FILE.exists():
                self._data = json.loads(COURSES_FILE.read_text(encoding="utf-8"))
        except Exception:
            self._data = {}

    def _save(self):
        COURSES_FILE.write_text(
            json.dumps(self._data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    # ── Courses ────────────────────────────────────────────────────────────────

    def list_courses(self) -> list:
        return list(self._data.values())

    def create_course(self, name: str) -> dict:
        cid = str(uuid.uuid4())
        folder = _unique_path(COURSES_DIR, _safe(name))
        folder.mkdir(parents=True, exist_ok=True)
        course = {
            "id": cid,
            "name": name,
            "folder": folder.name,
            "created_at": datetime.utcnow().isoformat(),
            "lessons": {},
        }
        self._data[cid] = course
        self._save()
        return course

    def get_course(self, cid: str) -> dict | None:
        return self._data.get(cid)

    def delete_course(self, cid: str):
        course = self._data.pop(cid, None)
        self._save()
        if course:
            d = COURSES_DIR / course["folder"]
            if d.exists():
                shutil.rmtree(d)

    # ── Lessons ────────────────────────────────────────────────────────────────

    def _next_num(self, cid: str) -> int:
        return len(self._data[cid]["lessons"]) + 1

    def _lesson_folder(self, cid: str, title: str) -> Path:
        course = self._data[cid]
        n = self._next_num(cid)
        base = _safe(f"שיעור {n} - {title}")
        return _unique_path(COURSES_DIR / course["folder"], base)

    def add_lesson_url(self, cid: str, title: str, url: str, job_id: str) -> dict:
        folder = self._lesson_folder(cid, title)
        folder.mkdir(parents=True, exist_ok=True)
        lid = str(uuid.uuid4())
        lesson = {
            "id": lid,
            "folder": folder.name,
            "title": title,
            "url": url,
            "video_filename": None,
            "video_size_mb": None,
            "download_job_id": job_id,
            "download_error": None,
            "transcript_txt": None,
            "transcript_srt": None,
            "transcript_job_id": None,
            "presentations": [],
            "created_at": datetime.utcnow().isoformat(),
        }
        self._data[cid]["lessons"][lid] = lesson
        self._save()
        return lesson

    def add_lesson_file(self, cid: str, title: str, src_path: Path) -> dict:
        folder = self._lesson_folder(cid, title)
        folder.mkdir(parents=True, exist_ok=True)
        dest = folder / f"video{src_path.suffix.lower()}"
        shutil.copy2(str(src_path), str(dest))
        size_mb = round(dest.stat().st_size / (1024 * 1024), 1)
        lid = str(uuid.uuid4())
        lesson = {
            "id": lid,
            "folder": folder.name,
            "title": title,
            "url": None,
            "video_filename": dest.name,
            "video_size_mb": size_mb,
            "download_job_id": None,
            "download_error": None,
            "transcript_txt": None,
            "transcript_srt": None,
            "transcript_job_id": None,
            "presentations": [],
            "created_at": datetime.utcnow().isoformat(),
        }
        self._data[cid]["lessons"][lid] = lesson
        self._save()
        return lesson

    def delete_lesson(self, cid: str, lid: str):
        course = self._data.get(cid, {})
        lesson = course.get("lessons", {}).pop(lid, None)
        self._save()
        if lesson:
            d = self.lesson_dir(cid, lid=None, folder=lesson["folder"], course_folder=course["folder"])
            if d.exists():
                shutil.rmtree(d)

    def update_lesson(self, cid: str, lid: str, **fields):
        lesson = self._data.get(cid, {}).get("lessons", {}).get(lid)
        if lesson:
            lesson.update(fields)
            self._save()

    def lesson_dir(self, cid: str, lid: str = None, folder: str = None, course_folder: str = None) -> Path:
        if folder and course_folder:
            return COURSES_DIR / course_folder / folder
        course = self._data[cid]
        lesson = course["lessons"][lid]
        return COURSES_DIR / course["folder"] / lesson["folder"]

    def get_lesson(self, cid: str, lid: str) -> dict | None:
        return self._data.get(cid, {}).get("lessons", {}).get(lid)

    # ── Presentations ──────────────────────────────────────────────────────────

    def add_presentation(self, cid: str, lid: str, src: Path) -> str:
        lesson = self._data[cid]["lessons"][lid]
        dest_dir = self.lesson_dir(cid, lid)
        dest_name = src.name
        dest = dest_dir / dest_name
        if dest.exists():
            stem, suffix = src.stem, src.suffix
            i = 2
            while (dest_dir / f"{stem}_{i}{suffix}").exists():
                i += 1
            dest_name = f"{stem}_{i}{suffix}"
            dest = dest_dir / dest_name
        shutil.copy2(str(src), str(dest))
        lesson.setdefault("presentations", []).append(dest_name)
        self._save()
        return dest_name

    def add_presentation_bytes(self, cid: str, lid: str, filename: str, data: bytes) -> str:
        lesson = self._data[cid]["lessons"][lid]
        dest_dir = self.lesson_dir(cid, lid)
        dest_name = filename
        dest = dest_dir / dest_name
        if dest.exists():
            stem, suffix = Path(filename).stem, Path(filename).suffix
            i = 2
            while (dest_dir / f"{stem}_{i}{suffix}").exists():
                i += 1
            dest_name = f"{stem}_{i}{suffix}"
            dest = dest_dir / dest_name
        dest.write_bytes(data)
        lesson.setdefault("presentations", []).append(dest_name)
        self._save()
        return dest_name

    def add_lesson_file_bytes(self, cid: str, title: str, filename: str, data: bytes) -> dict:
        folder = self._lesson_folder(cid, title)
        folder.mkdir(parents=True, exist_ok=True)
        suffix = Path(filename).suffix.lower() or ".mp4"
        dest = folder / f"video{suffix}"
        dest.write_bytes(data)
        size_mb = round(dest.stat().st_size / (1024 * 1024), 1)
        lid = str(uuid.uuid4())
        lesson = {
            "id": lid,
            "folder": folder.name,
            "title": title,
            "url": None,
            "video_filename": dest.name,
            "video_size_mb": size_mb,
            "download_job_id": None,
            "download_error": None,
            "transcript_txt": None,
            "transcript_srt": None,
            "transcript_job_id": None,
            "presentations": [],
            "created_at": datetime.utcnow().isoformat(),
        }
        self._data[cid]["lessons"][lid] = lesson
        self._save()
        return lesson

    def delete_presentation(self, cid: str, lid: str, filename: str):
        lesson = self._data.get(cid, {}).get("lessons", {}).get(lid)
        if lesson:
            lesson.setdefault("presentations", [])
            lesson["presentations"] = [f for f in lesson["presentations"] if f != filename]
            self._save()
        f = self.lesson_dir(cid, lid) / filename
        if f.exists():
            f.unlink()


db = CoursesDB()
