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
        # Update schedule status
        if now_utc < c.schedule_start:
            c.status = "SCHEDULED"
        elif c.schedule_start <= now_utc <= c.schedule_end:
            c.status = "OPEN"
        else:
            c.status = "CLOSED"
        result.append(c)
    return result

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

    course = Course(
        course_id=course_id,
        course_code=payload.course_code,
        title=payload.title,
        description=payload.description,
        instructor_name=payload.instructor_name,
        instructor_public_key=payload.instructor_public_key,
        capacity=payload.capacity,
        schedule_start=payload.schedule_start,
        schedule_end=payload.schedule_end,
        created_at=now_utc,
        enrolled_count=0,
        status="SCHEDULED"
    )
    db.add_course(course)
    return course
