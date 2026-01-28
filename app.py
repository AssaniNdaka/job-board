from flask import (
    Flask, render_template, request, redirect, url_for, flash, session,
    send_from_directory, send_file, jsonify
)
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os
import uuid
import io
import re
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from datetime import datetime

# ======================================================
# Flask App Config
# ======================================================
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change in production!

# Upload folders
BASE_UPLOAD_FOLDER = "static/uploads"
CV_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "cvs")
COVER_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "covers")
os.makedirs(CV_FOLDER, exist_ok=True)
os.makedirs(COVER_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = BASE_UPLOAD_FOLDER
app.config['CV_FOLDER'] = CV_FOLDER
app.config['COVER_FOLDER'] = COVER_FOLDER

# ======================================================
# File upload settings
# ======================================================
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}
PER_FILE_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
# Allow up to two files (CV + cover) so request-level set to slightly above 10MB
app.config['MAX_CONTENT_LENGTH'] = 11 * 1024 * 1024  # ~11 MB request cap

# ======================================================
# MySQL Configuration
# ======================================================
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Ndaka@2022'
app.config['MYSQL_DB'] = 'jobboard_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# ======================================================
# Helpers / Decorators
# ======================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash("Please login to continue.", "warning")
            # preserve next url if desired
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session or session.get('role') != 'admin':
            flash("Unauthorized: admins only", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def employer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session or session.get('role') != 'employer':
            flash("Unauthorized: employers only", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    """Check if file has allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_size(file_storage):
    """
    Safely get the size of an uploaded FileStorage object in bytes.
    We'll attempt to use the stream; if not available, fallback to reading bytes.
    """
    try:
        stream = file_storage.stream
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(0)
        return size
    except Exception:
        data = file_storage.read()
        size = len(data)
        try:
            file_storage.stream.seek(0)
        except Exception:
            pass
        return size

# ======================================================
# Error handlers
# ======================================================
@app.errorhandler(413)
def request_entity_too_large(e):
    flash("Uploaded files too large. Each file must be under 5MB.", "danger")
    return redirect(request.referrer or url_for('index'))

# ======================================================
# Public Pages
# ======================================================
@app.route('/', methods=['GET'])
def index():
    """
    Landing page:
    - shows a short list of available jobs (preview)
    - accepts optional query parameter 'q' to filter jobs (from search)
    """
    q = request.args.get('q', '').strip()
    cur = mysql.connection.cursor()
    if q:
        # search across title, description, company_name
        cur.execute("""
            SELECT j.id, j.title,
                   COALESCE(j.location, j.company_name, '') AS location,
                   j.company_name, j.created_at
            FROM jobs j
            WHERE j.title LIKE %s OR j.description LIKE %s OR j.company_name LIKE %s
            ORDER BY j.created_at DESC
            LIMIT 10
        """, (f'%{q}%', f'%{q}%', f'%{q}%'))
    else:
        # show recent 5 jobs for preview on landing page
        cur.execute("""
            SELECT j.id, j.title,
                   COALESCE(j.location, j.company_name, '') AS location,
                   j.company_name, j.created_at
            FROM jobs j
            ORDER BY j.created_at DESC
            LIMIT 5
        """)
    jobs = cur.fetchall()
    cur.close()
    return render_template('index.html', jobs=jobs, current_year=2025)

@app.route('/services')
def services():
    return render_template('services.html', current_year=2025)

@app.route('/about')
def about():
    return render_template('about.html', current_year=2025)

# ======================================================
# Contact
# ======================================================
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact form: saves messages to DB."""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        message = request.form.get('message', '').strip()

        if not name or not email or not message:
            flash("All fields are required", "danger")
            return redirect(url_for('contact'))

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO contact_messages (name, email, message, created_at) VALUES (%s, %s, %s, NOW())",
            (name, email, message)
        )
        mysql.connection.commit()
        cur.close()

        flash("Your message has been sent!", "success")
        return redirect(url_for('contact'))

    return render_template('contact.html', current_year=2025)

# ======================================================
# Registration / Login (with validation)
# ======================================================
EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")

def is_strong_password(pw: str) -> bool:
    """Basic strong password check: min 8 chars, upper, lower, digit."""
    if len(pw) < 8:
        return False
    if not re.search(r"[A-Z]", pw):
        return False
    if not re.search(r"[a-z]", pw):
        return False
    if not re.search(r"\d", pw):
        return False
    return True

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration (candidate, employer, admin)."""
    if request.method == 'POST':
        fullname = request.form.get('fullname', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role = request.form.get('user_type')

        if not fullname or not email or not password or not role:
            flash("All fields are required", "danger")
            return redirect(url_for('register'))

        if not EMAIL_REGEX.match(email):
            flash("Please provide a valid email address.", "danger")
            return redirect(url_for('register'))

        if not is_strong_password(password):
            flash("Password must be at least 8 characters long and include uppercase, lowercase and a number.", "danger")
            return redirect(url_for('register'))

        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        existing_user = cur.fetchone()

        if existing_user:
            flash("Email already exists", "warning")
            cur.close()
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        cur.execute(
            "INSERT INTO users (fullname, email, password, role, created_at) VALUES (%s, %s, %s, %s, NOW())",
            (fullname, email, hashed_password, role)
        )
        mysql.connection.commit()
        cur.close()

        flash("Registration successful. Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html', current_year=2025)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user['password'], password):
            session['loggedin'] = True
            session['user_id'] = user['id']
            session['fullname'] = user.get('fullname') or user.get('name') or ''
            session['email'] = user['email']
            session['role'] = user['role']

            flash("Login successful!", "success")
            # redirect candidates to browse_jobs, employers to dashboard
            if user['role'] == 'candidate':
                return redirect(url_for('browse_jobs'))
            return redirect(url_for('dashboard'))

        flash("Invalid email or password", "danger")
        return redirect(url_for('login'))

    return render_template('login.html', current_year=2025)

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for('index'))

# ======================================================
# Dashboard
# ======================================================
@app.route('/dashboard')
def dashboard():
    """Dashboard for candidate, employer, or admin."""
    if 'loggedin' not in session:
        flash("Please login first", "warning")
        return redirect(url_for('login'))

    role = session.get('role')
    user_id = session.get('user_id')

    jobs = applications = all_jobs = all_applications = messages = []
    total_candidates = total_employers = total_admins = total_jobs = total_applications = 0
    applications_per_job = []

    cur = mysql.connection.cursor()

    if role == 'employer':
        cur.execute("""
            SELECT j.id, j.title, j.company_name, j.created_at,
                   COUNT(a.id) AS applicant_count
            FROM jobs j
            LEFT JOIN applications a ON j.id=a.job_id
            WHERE j.employer_id=%s
            GROUP BY j.id
            ORDER BY j.created_at DESC
        """, (user_id,))
        jobs = cur.fetchall()

        cur.execute("""
            SELECT a.id, u.fullname AS candidate_name, u.email AS candidate_email,
                   j.title AS job_title, a.cv_file, a.cover_letter, a.status, a.applied_at
            FROM applications a
            JOIN users u ON a.user_id=u.id
            JOIN jobs j ON a.job_id=j.id
            WHERE j.employer_id=%s
            ORDER BY a.applied_at DESC
        """, (user_id,))
        applications = cur.fetchall()

    elif role == 'candidate':
        cur.execute("""
            SELECT a.id, j.title AS job_title, a.status, a.applied_at
            FROM applications a
            JOIN jobs j ON a.job_id=j.id
            WHERE a.user_id=%s
            ORDER BY a.applied_at DESC
        """, (user_id,))
        applications = cur.fetchall()

    elif role == 'admin':
        cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE role='candidate'")
        total_candidates = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE role='employer'")
        total_employers = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE role='admin'")
        total_admins = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(*) AS cnt FROM jobs")
        total_jobs = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(*) AS cnt FROM applications")
        total_applications = cur.fetchone()['cnt']

        cur.execute("""
            SELECT j.title, COUNT(a.id) AS cnt
            FROM jobs j
            LEFT JOIN applications a ON j.id=a.job_id
            GROUP BY j.id
            ORDER BY cnt DESC
        """)
        applications_per_job = [(r['title'], r['cnt']) for r in cur.fetchall()]

        cur.execute("""
            SELECT j.id, j.title, DATE_FORMAT(j.created_at,'%%Y-%%m-%%d') AS posted_on,
                   u.fullname AS employer_name,
                   COUNT(a.id) AS applicant_count
            FROM jobs j
            JOIN users u ON j.employer_id=u.id
            LEFT JOIN applications a ON j.id=a.job_id
            GROUP BY j.id
            ORDER BY j.created_at DESC
        """)
        all_jobs = cur.fetchall()

        cur.execute("""
            SELECT u.fullname AS candidate_name, j.title AS job_title,
                   DATE_FORMAT(a.applied_at,'%%Y-%%m-%%d') AS applied_on, a.status
            FROM applications a
            JOIN users u ON a.user_id=u.id
            JOIN jobs j ON a.job_id=j.id
            ORDER BY a.applied_at DESC
        """)
        all_applications = cur.fetchall()

        cur.execute("SELECT * FROM contact_messages ORDER BY created_at DESC")
        messages = cur.fetchall()

    cur.close()

    return render_template('dashboard.html',
                           jobs=jobs,
                           applications=applications,
                           all_jobs=all_jobs,
                           all_applications=all_applications,
                           messages=messages,
                           total_candidates=total_candidates,
                           total_employers=total_employers,
                           total_admins=total_admins,
                           total_jobs=total_jobs,
                           total_applications=total_applications,
                           applications_per_job=applications_per_job,
                           current_year=2025)

# ======================================================
# Employer: Jobs
# ======================================================
@app.route('/post-job', methods=['GET', 'POST'])
@employer_required
def post_job():
    """Employer posts a job."""
    if request.method == 'POST':
        title = request.form.get('title')
        company_name = request.form.get('company_name')
        description = request.form.get('description')
        requirements = request.form.get('requirements')
        why_work_with_us = request.form.get('why_work_with_us')
        mission = request.form.get('mission')
        vision = request.form.get('vision')
        location = request.form.get('location')

        if not title or not company_name or not description or not requirements:
            flash("Title, company name, description, and requirements are required", "danger")
            return redirect(url_for('post_job'))

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO jobs (employer_id, title, company_name, description, requirements,
                              why_work_with_us, mission, vision, location, created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
        """, (session['user_id'], title, company_name, description, requirements,
              why_work_with_us, mission, vision, location))
        mysql.connection.commit()
        cur.close()

        flash("Job posted successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('post_job.html', current_year=2025)

@app.route('/edit-job/<int:job_id>', methods=['GET', 'POST'])
@employer_required
def edit_job(job_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM jobs WHERE id=%s AND employer_id=%s", (job_id, session['user_id']))
    job = cur.fetchone()

    if not job:
        cur.close()
        flash("Job not found or unauthorized", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form.get('title')
        company_name = request.form.get('company_name')
        description = request.form.get('description')
        requirements = request.form.get('requirements')
        why_work_with_us = request.form.get('why_work_with_us')
        mission = request.form.get('mission')
        vision = request.form.get('vision')
        location = request.form.get('location')

        cur.execute("""
            UPDATE jobs SET title=%s, company_name=%s, description=%s, requirements=%s,
                            why_work_with_us=%s, mission=%s, vision=%s, location=%s
            WHERE id=%s AND employer_id=%s
        """, (title, company_name, description, requirements,
              why_work_with_us, mission, vision, location, job_id, session['user_id']))
        mysql.connection.commit()
        cur.close()

        flash("Job updated successfully!", "success")
        return redirect(url_for('dashboard'))

    cur.close()
    return render_template('edit_job.html', job=job, current_year=2025)

@app.route('/delete-job/<int:job_id>', methods=['POST'])
@employer_required
def delete_job(job_id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM jobs WHERE id=%s AND employer_id=%s", (job_id, session['user_id']))
    mysql.connection.commit()
    cur.close()

    flash("Job deleted successfully!", "success")
    return redirect(url_for('dashboard'))

# ======================================================
# Candidate: Jobs & Applications
# ======================================================
@app.route('/browse_jobs')
def browse_jobs():
    q = request.args.get('q', '').strip()
    cur = mysql.connection.cursor()
    if q:
        cur.execute("""
            SELECT j.id, j.title, j.description, j.requirements, j.why_work_with_us,
                   j.mission, j.vision, j.company_name, j.location, j.created_at,
                   u.fullname AS employer_name
            FROM jobs j
            JOIN users u ON j.employer_id=u.id
            WHERE j.title LIKE %s OR j.description LIKE %s OR j.company_name LIKE %s
            ORDER BY j.created_at DESC
        """, (f'%{q}%', f'%{q}%', f'%{q}%'))
    else:
        cur.execute("""
            SELECT j.id, j.title, j.description, j.requirements, j.why_work_with_us,
                   j.mission, j.vision, j.company_name, j.location, j.created_at,
                   u.fullname AS employer_name
            FROM jobs j
            JOIN users u ON j.employer_id=u.id
            ORDER BY j.created_at DESC
        """)
    jobs = cur.fetchall()
    cur.close()
    return render_template('browse_jobs.html', jobs=jobs, query=q, current_year=2025)

@app.route('/search')
def search():
    # alias to /browse_jobs (keeps compatibility with templates)
    return redirect(url_for('browse_jobs', q=request.args.get('q', '').strip()))

@app.route('/job/<int:job_id>')
@login_required
def job_detail(job_id):
    # User must be logged in to view job details
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT j.id, j.title, j.company_name, j.location, j.description, j.requirements,
               j.why_work_with_us, j.mission, j.vision, j.created_at,
               u.fullname AS employer_name
        FROM jobs j
        JOIN users u ON j.employer_id=u.id
        WHERE j.id=%s
    """, (job_id,))
    job = cur.fetchone()
    cur.close()

    if not job:
        flash("Job not found", "danger")
        return redirect(url_for('browse_jobs'))

    return render_template('job_detail.html', job=job, current_year=2025)

@app.route('/apply/<int:job_id>', methods=['GET', 'POST'])
def apply(job_id):
    # Application logic here
    ...
def apply(job_id):
    """Candidate: apply for a job. Accepts CV file and cover letter file (or text)."""
    if 'loggedin' not in session or session.get('role') != 'candidate':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    cv_file = request.files.get('cv') or request.files.get('cv_file')  # accept either name
    cover_file = request.files.get('cover_letter')  # if cover letter uploaded as file
    cover_text = request.form.get('cover_letter_text')  # if cover letter as text area

    if not cv_file:
        flash("CV is required", "danger")
        return redirect(url_for('job_detail', job_id=job_id))

    # Validate filename & extension
    if not cv_file.filename or not allowed_file(cv_file.filename):
        flash("CV must be PDF or Word (.pdf/.doc/.docx)", "danger")
        return redirect(url_for('job_detail', job_id=job_id))

    # Per-file size checks
    cv_size = get_file_size(cv_file)
    if cv_size > PER_FILE_MAX_BYTES:
        flash("CV exceeds 5MB limit", "danger")
        return redirect(url_for('job_detail', job_id=job_id))

    cover_filename_saved = None
    cover_text_to_store = None
    if cover_file and cover_file.filename:
        if not allowed_file(cover_file.filename):
            flash("Cover letter must be PDF or Word (.pdf/.doc/.docx)", "danger")
            return redirect(url_for('job_detail', job_id=job_id))
        cover_size = get_file_size(cover_file)
        if cover_size > PER_FILE_MAX_BYTES:
            flash("Cover letter exceeds 5MB limit", "danger")
            return redirect(url_for('job_detail', job_id=job_id))

    # If user provided text in a textarea instead of a file
    if cover_text and not cover_file:
        cover_text_to_store = cover_text.strip()

    # Save CV
    cv_filename = secure_filename(cv_file.filename)
    unique_cv = f"{uuid.uuid4().hex}_{cv_filename}"
    cv_path = os.path.join(app.config['CV_FOLDER'], unique_cv)
    cv_file.save(cv_path)

    # Save cover file if present
    if cover_file and cover_file.filename:
        cover_filename = secure_filename(cover_file.filename)
        unique_cover = f"{uuid.uuid4().hex}_{cover_filename}"
        cover_path = os.path.join(app.config['COVER_FOLDER'], unique_cover)
        cover_file.save(cover_path)
        cover_filename_saved = unique_cover

    # Insert application record
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO applications (user_id, job_id, cv_file, cover_letter, status, applied_at)
        VALUES (%s, %s, %s, %s, %s, NOW())
    """, (session['user_id'], job_id, unique_cv, cover_filename_saved or cover_text_to_store, 'Pending'))
    mysql.connection.commit()
    cur.close()

    flash("Application submitted successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/cv/<path:filename>')
def view_cv(filename):
    """Serve uploaded CVs securely (ensure proper auth in production)."""
    return send_from_directory(app.config['CV_FOLDER'], filename, as_attachment=False)

@app.route('/cover/<path:filename>')
def view_cover(filename):
    return send_from_directory(app.config['COVER_FOLDER'], filename, as_attachment=False)

# ======================================================
# Employer: Applicants view (now passes job details too)
# ======================================================
@app.route('/job/<int:job_id>/applicants')
@employer_required
def view_applicants(job_id):
    """Employer: view all applicants for a specific job."""
    # Check employer owns the job and fetch job details
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM jobs WHERE id=%s AND employer_id=%s", (job_id, session['user_id']))
    job = cur.fetchone()
    if not job:
        cur.close()
        flash("Job not found or unauthorized", "danger")
        return redirect(url_for('dashboard'))

    cur.execute("""
        SELECT a.id, u.fullname AS candidate_name, u.email AS candidate_email,
               a.cv_file, a.cover_letter, a.status, a.applied_at
        FROM applications a
        JOIN users u ON a.user_id=u.id
        WHERE a.job_id=%s
        ORDER BY a.applied_at DESC
    """, (job_id,))
    applicants = cur.fetchall()
    cur.close()

    return render_template('view_applicants.html', applicants=applicants, job_id=job_id, job=job, current_year=2025)

# ======================================================
# Employer: Update application status
# ======================================================
@app.route('/application/<int:application_id>/update_status', methods=['POST'])
@employer_required
def update_applicant_status(application_id):
    """
    Employer can change applicant status:
    - Ensure the employer owns the job that this application belongs to
    - Allowed statuses: Pending, Shortlisted, Rejected, Hired, Accepted
    """
    new_status = request.form.get('status')
    allowed_statuses = {'Pending', 'Shortlisted', 'Rejected', 'Hired', 'Accepted'}
    if new_status not in allowed_statuses:
        flash("Invalid status", "danger")
        return redirect(request.referrer or url_for('dashboard'))

    cur = mysql.connection.cursor()
    # find job_id for this application and ensure current employer owns it
    cur.execute("SELECT job_id FROM applications WHERE id=%s", (application_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        flash("Application not found", "danger")
        return redirect(url_for('dashboard'))

    job_id = row['job_id']
    cur.execute("SELECT employer_id FROM jobs WHERE id=%s", (job_id,))
    job_row = cur.fetchone()
    if not job_row or job_row['employer_id'] != session.get('user_id'):
        cur.close()
        flash("Unauthorized to change this application's status", "danger")
        return redirect(url_for('dashboard'))

    cur.execute("UPDATE applications SET status=%s WHERE id=%s", (new_status, application_id))
    mysql.connection.commit()
    cur.close()

    flash("Application status updated", "success")
    return redirect(url_for('view_applicants', job_id=job_id))

# Backwards-compatible alias (if other parts still use the old route name)
@app.route('/application/<int:app_id>/update_status', methods=['POST'])
@employer_required
def update_application_status(app_id):
    return update_applicant_status(app_id)

# ======================================================
# Admin Dashboard & APIs (Step 4)
# ======================================================
@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    """
    Admin dashboard page: pass real figures to the template for cards, tables and charts.
    """
    cur = mysql.connection.cursor()

    # Total counts
    cur.execute("SELECT COUNT(*) AS cnt FROM users")
    total_users = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) AS cnt FROM jobs")
    total_jobs = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) AS cnt FROM applications")
    total_applications = cur.fetchone()['cnt']

    # Counts by role
    cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE role='candidate'")
    total_candidates = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE role='employer'")
    total_employers = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE role='admin'")
    total_admins = cur.fetchone()['cnt']

    # Applications by status
    cur.execute("SELECT status, COUNT(*) AS cnt FROM applications GROUP BY status")
    status_rows = cur.fetchall()
    # Normalize statuses to known keys (so the template has values even if 0)
    status_counts = {'Pending': 0, 'Shortlisted': 0, 'Rejected': 0, 'Hired': 0, 'Accepted': 0}
    for r in status_rows:
        st = r['status'] or 'Pending'
        status_counts[st] = r['cnt']

    # Top jobs by application count (limit 10)
    cur.execute("""
        SELECT j.title, COUNT(a.id) AS cnt
        FROM jobs j
        LEFT JOIN applications a ON j.id=a.job_id
        GROUP BY j.id
        ORDER BY cnt DESC
        LIMIT 10
    """)
    top_jobs = cur.fetchall()

    # Recent applications (limit 10)
    cur.execute("""
        SELECT u.fullname AS candidate_name, j.title AS job_title,
               DATE_FORMAT(a.applied_at,'%%Y-%%m-%%d %%H:%%i') AS applied_on, a.status
        FROM applications a
        JOIN users u ON a.user_id=u.id
        JOIN jobs j ON a.job_id=j.id
        ORDER BY a.applied_at DESC
        LIMIT 10
    """)
    recent_apps = cur.fetchall()

    cur.close()

    return render_template(
        'admin_dashboard.html',
        total_users=total_users,
        total_jobs=total_jobs,
        total_applications=total_applications,
        total_candidates=total_candidates,
        total_employers=total_employers,
        total_admins=total_admins,
        status_counts=status_counts,
        top_jobs=top_jobs,
        recent_apps=recent_apps,
        current_year=2025
    )

@app.route('/admin/stats_json')
@admin_required
def admin_stats_json():
    """
    JSON endpoint for admin stats (useful for Chart.js AJAX).
    """
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) AS cnt FROM users")
    total_users = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) AS cnt FROM jobs")
    total_jobs = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) AS cnt FROM applications")
    total_applications = cur.fetchone()['cnt']

    cur.execute("SELECT status, COUNT(*) AS cnt FROM applications GROUP BY status")
    status_rows = cur.fetchall()
    status_counts = {'Pending': 0, 'Shortlisted': 0, 'Rejected': 0, 'Hired': 0, 'Accepted': 0}
    for r in status_rows:
        status_counts[r['status'] or 'Pending'] = r['cnt']

    # top jobs
    cur.execute("""
        SELECT j.title, COUNT(a.id) AS cnt
        FROM jobs j
        LEFT JOIN applications a ON j.id=a.job_id
        GROUP BY j.id
        ORDER BY cnt DESC
        LIMIT 10
    """)
    top_jobs = cur.fetchall()

    cur.close()

    return jsonify({
        'total_users': total_users,
        'total_jobs': total_jobs,
        'total_applications': total_applications,
        'status_counts': status_counts,
        'top_jobs': top_jobs
    })

# ======================================================
# Admin Messages & Reports
# ======================================================
@app.route('/admin/messages')
@admin_required
def admin_messages():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM contact_messages ORDER BY created_at DESC")
    messages = cur.fetchall()
    cur.close()
    return render_template('admin_messages.html', messages=messages, current_year=2025)

@app.route('/admin/messages/delete/<int:msg_id>', methods=['POST'])
@admin_required
def delete_message(msg_id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM contact_messages WHERE id=%s", (msg_id,))
    mysql.connection.commit()
    cur.close()
    flash("Message deleted", "success")
    return redirect(url_for('admin_messages'))

@app.route('/download_report')
@admin_required
def download_report():
    """
    Admin: download a PDF report with real figures pulled from DB.
    """
    cur = mysql.connection.cursor()
    # Basic counts
    cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE role='candidate'")
    total_candidates = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE role='employer'")
    total_employers = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE role='admin'")
    total_admins = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) AS cnt FROM jobs")
    total_jobs = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) AS cnt FROM applications")
    total_applications = cur.fetchone()['cnt']

    # Top jobs by applications
    cur.execute("""
        SELECT j.title, COUNT(a.id) AS cnt
        FROM jobs j
        LEFT JOIN applications a ON j.id=a.job_id
        GROUP BY j.id
        ORDER BY cnt DESC
        LIMIT 10
    """)
    top_jobs = cur.fetchall()

    # Recent applications (limit 10)
    cur.execute("""
        SELECT u.fullname AS candidate_name, j.title AS job_title,
               DATE_FORMAT(a.applied_at,'%%Y-%%m-%%d') AS applied_on, a.status
        FROM applications a
        JOIN users u ON a.user_id=u.id
        JOIN jobs j ON a.job_id=j.id
        ORDER BY a.applied_at DESC
        LIMIT 10
    """)
    recent_apps = cur.fetchall()

    cur.close()

    # Build PDF
    pdf_buffer = io.BytesIO()
    p = canvas.Canvas(pdf_buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, 750, "Job Board - Admin Report")
    p.setFont("Helvetica", 11)
    y = 730
    p.drawString(50, y, f"Generated by: {session.get('fullname', 'admin')}")
    y -= 20
    p.drawString(50, y, f"Total candidates: {total_candidates}")
    y -= 15
    p.drawString(50, y, f"Total employers: {total_employers}")
    y -= 15
    p.drawString(50, y, f"Total admins: {total_admins}")
    y -= 15
    p.drawString(50, y, f"Total jobs posted: {total_jobs}")
    y -= 15
    p.drawString(50, y, f"Total applications: {total_applications}")
    y -= 25

    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, y, "Top jobs by application count:")
    y -= 18
    p.setFont("Helvetica", 11)
    if top_jobs:
        for r in top_jobs:
            p.drawString(60, y, f"{r['title']} — {r['cnt']} applications")
            y -= 14
            if y < 80:
                p.showPage()
                y = 750
    else:
        p.drawString(60, y, "No job data.")
        y -= 14

    y -= 10
    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, y, "Recent applications:")
    y -= 18
    p.setFont("Helvetica", 11)
    if recent_apps:
        for a in recent_apps:
            p.drawString(60, y, f"{a['applied_on']} - {a['candidate_name']} -> {a['job_title']} [{a['status']}]")
            y -= 14
            if y < 80:
                p.showPage()
                y = 750
    else:
        p.drawString(60, y, "No recent applications.")
        y -= 14

    p.showPage()
    p.save()
    pdf_buffer.seek(0)

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name="jobboard_report.pdf",
        mimetype='application/pdf'
    )

# ======================================================
# Run App
# ======================================================
if __name__ == '__main__':
    # debug True for development; set to False in production and set proper secret key
    app.run(debug=True)
