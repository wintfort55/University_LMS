import csv
import datetime
import os
import pytz
import requests
import urllib
import uuid

from cs50 import SQL
from datetime import datetime, timedelta
from flask import redirect, render_template, request, session, current_app as app
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///lms.db")


def apology(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def allowed_file(filename, allowed_extensions):
    extension = '.' + filename.rsplit('.', 1)[1].lower()
    return '.' in filename and extension in allowed_extensions


def upload_img(file, allowed_extensions):
    try:
        extension = os.path.splitext(file.filename)[1].lower()

        if file and allowed_file(file.filename, allowed_extensions):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_IMG_DIRECTORY'], filename))
            return filename
        else:
            return None
    except RequestEntityTooLarge:
        return apology("File is larger than 16MB limit", 400)
    

def upload_doc(file, allowed_extensions):
    try:
        extension = os.path.splitext(file.filename)[1].lower()

        if file and allowed_file(file.filename, allowed_extensions):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_DOC_DIRECTORY'], filename))
            return filename
        else:
            return None
    except RequestEntityTooLarge:
        return apology("File is larger than 16MB limit", 400)


# Update user's PREVIOUS lesson grades (completed, completed time, lesson grade)
def update_lg_sg(section_id, prev_lesson, users_id):

    # Get time for database updates:
    now_utc = datetime.now(pytz.UTC)

    # Update Lesson grade
    # Check if HW grade, if not update lesson grade with quiz grade
    current_grades = db.execute("SELECT lesson_hw_grade, lesson_quiz_grade FROM lesson_grades WHERE lg_lesson_id = ? AND lg_user_id = ?", prev_lesson, users_id)
    # print(f"HELPERS - UPDATE Prev Les Grade (current_grades): {current_grades}")

    # CONSTANT dependent on how many (quiz,hw) columns being averaged in lesson grade
    if current_grades:
        current_hw_grade = current_grades[0]['lesson_hw_grade']
        current_quiz_grade = current_grades[0]['lesson_quiz_grade']
        if current_hw_grade is not None:
            new_lesson_grade = int((current_hw_grade + current_quiz_grade)/2)
        else:
            if current_quiz_grade is not None:
                new_lesson_grade = current_quiz_grade
            else:
                new_lesson_grade = 100
    
    # Update section grade with added lesson's grade
    sec_grade = db.execute("SELECT section_grade FROM section_grades WHERE sg_section_id = ? AND sg_user_id = ?", section_id, users_id)
    if sec_grade:
        section_grade = sec_grade[0]['section_grade']
        if section_grade is not None:
            new_section_grade = int((section_grade + new_lesson_grade)/2)
        else:
            new_section_grade = new_lesson_grade

    # Update Lesson Grade
    db.execute(
        """UPDATE lesson_grades SET (lesson_completed, lesson_completed_datetime, lesson_grade) = (?, ?, ?) 
        WHERE lg_lesson_id = ? AND lg_user_id = ?""", 1, now_utc, new_lesson_grade, prev_lesson, users_id)
    
    # Update Section Grade
    db.execute(
        """UPDATE section_grades SET (section_grade) = (?) WHERE sg_section_id = ? AND sg_user_id = ?""", new_section_grade, section_id, users_id)
    
    return 


# Mark prev section grades complete with complete datetime
def mark_sec_complete(section_id, users_id):

    # Get time for database updates:
    now_utc = datetime.now(pytz.UTC)

    db.execute(
        """UPDATE section_grades SET (section_completed, section_completed_datetime) = (?, ?) WHERE sg_section_id = ? AND sg_user_id = ?""", 1, now_utc, section_id, users_id)
    
    return

# If multiple lessons in final section, update below
def mark_course_complete(course_id, users_id):

    # Get time for database updates:
    now_utc = datetime.now(pytz.UTC)

    db.execute(
        """UPDATE course_grades SET (course_completed, course_completed_datetime) = (?, ?) WHERE cg_course_id = ? AND cg_user_id = ?""", 1, now_utc, course_id, users_id)
    
    return


# If only one lesson in final section, update below
def update_final_lesson(lesson_id, section_id, course_id, users_id):
    
    # Get time for database updates:
    now_utc = datetime.now(pytz.UTC)

    # Update final course grade
    update_course_final_grade(course_id, users_id)
    
    # Lesson grades
    db.execute(
        """UPDATE lesson_grades SET (lesson_completed, lesson_completed_datetime, lesson_grade) = (?, ?, ?) WHERE lg_lesson_id = ? AND lg_lesson_id = ?""", 1, now_utc, 100, lesson_id, users_id)
    
    # Section grades
    db.execute(
        """UPDATE section_grades SET (section_completed, section_completed_datetime, section_grade) = (?, ?, ?) WHERE sg_section_id = ? AND sg_user_id = ?""", 1, now_utc, 100, section_id, users_id)

    # Course grades
    db.execute(
        """UPDATE course_grades SET (course_completed, course_completed_datetime) = (?, ?) WHERE cg_course_id = ? AND cg_user_id = ?""", 1, now_utc, course_id, users_id)
    
    return


# Update final course grade
def update_course_final_grade(course_id, users_id):

    # Get Avg of all section grades in course
    avg = db.execute(
        """SELECT AVG(section_grade) FROM section_grades JOIN sections ON section_grades.sg_section_id = sections.section_id WHERE sections.section_course_id = ?""", course_id)
    if avg:
        section_grade_avg = avg[0]['AVG(section_grade)']

    # Update course grade
    db.execute(
        """UPDATE course_grades SET (course_grade) = (?) WHERE cg_course_id = ? AND cg_user_id = ?""", section_grade_avg, course_id, users_id)

    return

# Check question count for quiz
def question_count(quiz_id):
    questions = db.execute(
        """SELECT * FROM questions WHERE question_quiz_id = ? ORDER BY question_number ASC""", quiz_id)
    if questions:
        question_count = len(questions)
        return question_count
    

