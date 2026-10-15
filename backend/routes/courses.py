import uuid
import datetime
from fastapi import APIRouter, HTTPException
from typing import List
from core.models import Course, CourseCreate
from backend.database import db

router = APIRouter(prefix="/courses", tags=["Courses"])

@router.get("", response_model=List[Course])
def list_courses():
    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = []
    for c in db.courses.values():
        if c.is_timed and c.schedule_start and c.schedule_end:
            if now_utc < c.schedule_start:
                c.status = "SCHEDULED"
                c.is_enrollment_open = False
            elif c.schedule_start <= now_utc <= c.schedule_end:
                c.status = "OPEN"
                c.is_enrollment_open = True
            else:
                c.status = "CLOSED"
                c.is_enrollment_open = False
        else:
            c.status = "OPEN" if c.is_enrollment_open else "PENDING_START"
        result.append(c)
    return result

@router.get("/code/{code}", response_model=Course)
def get_course_by_code(code: str):
    course = db.get_course_by_code(code)
    if not course:
        raise HTTPException(status_code=404, detail=f"Course with code '{code}' not found")
    return course

@router.get("/{course_id}", response_model=Course)
def get_course(course_id: str):
    course = db.get_course(course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    return course

@router.post("", response_model=Course)
def create_course(payload: CourseCreate):
    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    course_id = payload.course_code.upper().replace(" ", "-")
    if course_id in db.courses:
        course_id = f"{course_id}-{str(uuid.uuid4())[:4]}"

    # If untimed, starts in PENDING_START mode until instructor starts it
    is_open = False
    if payload.is_timed and payload.schedule_start and payload.schedule_end:
        is_open = (payload.schedule_start <= now_utc <= payload.schedule_end)

    course = Course(
        course_id=course_id,
        course_code=payload.course_code,
        title=payload.title,
        description=payload.description,
        instructor_name=payload.instructor_name,
        instructor_email=payload.instructor_email,
        instructor_public_key=payload.instructor_public_key,
        capacity=payload.capacity,
        is_timed=payload.is_timed,
        schedule_start=payload.schedule_start,
        schedule_end=payload.schedule_end,
        is_enrollment_open=is_open,
        created_at=now_utc,
        enrolled_count=0,
        status="OPEN" if is_open else "PENDING_START"
    )
    db.add_course(course)
    return course

@router.post("/{course_id}/toggle-enrollment")
def toggle_enrollment(course_id: str):
    course = db.get_course(course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    new_state = not course.is_enrollment_open
    updated = db.toggle_course_enrollment(course_id, new_state)
    return {
        "course_id": course_id,
        "is_enrollment_open": updated.is_enrollment_open,
        "status": updated.status
    }
