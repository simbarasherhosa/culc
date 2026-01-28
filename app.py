from flask_migrate import Migrate
import json
from flask import Flask, send_from_directory, render_template, request, jsonify, flash, session, url_for, redirect
import os 
from models import Application, db, User, Profile, Job, Applicant, Employer
from config import BASE_DIR, SQLALCHEMY_DATABASE_URI, SECRET_KEY, IS_PRODUCTION
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from resume_utils import extract_text_from_pdf, extract_text_from_docx, extract_skills
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import re
from flask_mail import Mail
from config import (
    MAIL_PASSWORD,
    MAIL_PORT,
    MAIL_SERVER,
    MAIL_USE_TLS,
    MAIL_USERNAME,
    MAIL_DEFAULT_SENDER
)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, TextAreaField, SelectField, DecimalField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange
from decimal import Decimal
from flask_sqlalchemy import SQLAlchemy

migrate = Migrate()
csrf = CSRFProtect()


def create_app():
    import os
    app = Flask(__name__)

    # Production Configuration
    if IS_PRODUCTION:
        app.config["ENV"]
        app.config["DEBUG"] = False
        app.config["TESTING"] = False

        # Security headers

        @app.after_request
        def set_security_headers(response):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            if 'Cache-Control' not in response.headers:
                response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
                return response
            else:
                app.config["DEBUG"] = True

    app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = SECRET_KEY

    # Configurations
    app.config["MAIL_SERVER"] = MAIL_SERVER
    app.config["MAIL_PORT"] = MAIL_PORT
    app.config["MAIL_USE_TLS"] = MAIL_USE_TLS
    app.config["MAIL_USERNAME"] = MAIL_USERNAME
    app.config["MAIL_PASSWORD"] = MAIL_PASSWORD
    app.config["MAIL_DEFAULT_SENDER"] = MAIL_DEFAULT_SENDER

    # UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), "uploads")
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    ALLOWED_EXTENSIONS = {"pdf", "doc", "docx"}
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024 #16MB


    db.init_app(app)
    migrate.init_app(app, db)
    mail = Mail(app)
    csrf.init_app(app)

    @app.errorhandler(404)
    def not_found(error):
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('500.html'), 500

    @app.errorhandler(413)
    def too_large(error):
        flash("File too large. Maximum size is 16MB.", "danger")
        return redirect(request.referrer or url_for('upload_resume'))

    login_manager = LoginManager()
    login_manager.login_view = "login"  # redirect users to login page if not logged in
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return User.query.get(int(user_id))
        except Exception as e:
            print(f"Error loading user: {e}")
            return None

    def get_seeker_skills(profile):
        """Extract seeker skills from profile and resume text."""
        skills = []

        try:
            if hasattr(profile, "skills") and profile.skills:
                if isinstance(profile.skills, str):
                    skills += [s.strip().lower() for s in profile.skills.split(",") if s.strip()]
                else:
                    skills += profile.skills

            if profile.resume:
                resume_path = os.path.join(app.config["UPLOAD_FOLDER"], profile.resume)
                text = ""
                if resume_path.endswith(".pdf"):
                    text = extract_text_from_pdf(resume_path)
                elif resume_path.endswith(".docx"):
                    text = extract_text_from_docx(resume_path)
                skills += extract_skills(text)

            return list(set(skills))
        except Exception as e:
            print(f"Error extracting skills: {e}")
            return []

    def allowed_file(filename):
        return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

    @app.route("/upload_resume", methods=["GET", "POST"])
    @login_required
    def upload_resume():
        try:
            profile = Profile.query.filter_by(user_id=current_user.id).first()
            extracted_skills = session.get("extracted_skills", None)
        except Exception as e:
            flash("Error loading profile", "danger")
            print(f"Database error in upload_resume: {e}")
            return redirect(url_for("seeker_dashboard"))

        if request.method == "POST":
            file = request.files.get("resume")
            if not file or file.filename == "":
                flash("No file selected", "warning")
                return redirect(url_for("upload_resume"))

            if not allowed_file(file.filename):
                flash("Unsupported file format", "danger")
                return redirect(url_for("upload_resume"))

            try:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(file_path)

                # Extract text from resume
                if filename.endswith(".pdf"):
                    text = extract_text_from_pdf(file_path)
                else:
                    text = extract_text_from_docx(file_path)

                extracted_skills = extract_skills(text) or []

                # Save temporarily in session for modal display
                session["resume_filename"] = filename
                session["extracted_skills"] = extracted_skills

                return render_template(
                    "upload_resume.html",
                    profile=profile,
                    extracted_skills=extracted_skills
                )
            except Exception as e:
                flash("Error processing resume file", "danger")
                print(f"File processing error: {e}")
                return redirect(url_for("upload_resume"))

        # GET request: render page normally
        return render_template("upload_resume.html", profile=profile, extracted_skills=extracted_skills)

    @app.route("/save_skills", methods=["POST"])
    @login_required
    def save_skills():
        try:
            selected_skills = request.form.getlist("skills")
            filename = session.get("resume_filename")

            profile = Profile.query.filter_by(user_id=current_user.id).first()
            if not profile:
                profile = Profile(user_id=current_user.id)
                db.session.add(profile)

            # Save resume and skills permanently
            profile.resume = filename
            custom_skills = request.form.get("custom_skills", "")
            if custom_skills:
                selected_skills += [s.strip() for s in custom_skills.split(",") if s.strip()]

            profile.skills = ",".join(selected_skills)
            db.session.commit()

            # Remove temporary session data
            session.pop("resume_filename", None)
            session.pop("extracted_skills", None)

            flash("Skills and resume saved successfully!", "success")
            return redirect(url_for("upload_resume"))
        except Exception as e:
            db.session.rollback()
            flash("Error saving skills", "danger")
            print(f"Database error in save_skills: {e}")
            return redirect(url_for("upload_resume"))

    @app.route("/uploads/<filename>")
    @login_required
    def uploaded_file(filename):
        try:
            return send_from_directory(app.config["UPLOAD_FOLDER"], filename)
        except Exception as e:
            flash("File not found", "danger")
            print(f"File error: {e}")
            return redirect(url_for("seeker_dashboard"))

    from rapidfuzz import fuzz
    import re

    def normalize_skill(skill):
        """Clean and normalize skill strings."""
        return re.sub(r'[^a-z0-9 ]', '', skill.lower()).strip()

    def calculate_match(user_skills, job_skills):
        """Return matched skills and match score with fuzzy logic."""
        matched_skills = []
        for js in job_skills:
            js_norm = normalize_skill(js)
            for us in user_skills:
                us_norm = normalize_skill(us)
                if fuzz.partial_ratio(js_norm, us_norm) >= 80:
                    matched_skills.append(js)
                    break
        score = len(matched_skills) / len(job_skills) if job_skills else 0
        return matched_skills, score

    @app.route("/dashboard")
    @login_required
    def seeker_dashboard():
        if current_user.role != "seeker":
            flash("Access denied!", "danger")
            return redirect(url_for("index"))

        try:
            profile = Profile.query.filter_by(user_id=current_user.id).first()
            if not profile:
                flash("Please complete your profile first.", "warning")
                return redirect(url_for("create_profile"))
            
            applicant_profile = Applicant.query.filter_by(user_id=current_user.id).first()
            if not applicant_profile:
                flash("Please complete your registration profile.", "warning")
                return redirect(url_for("register"))

            # --- User skills ---
            user_skills = [s.strip().lower() for s in profile.skills.split(",")] if profile.skills else []

            # --- Fetch all jobs ---
            all_jobs = Job.query.all()

            applied_job_ids = [app.job_id for app in Application.query.filter_by(applicant_id=applicant_profile.id).all()]
            applied_jobs, recommended_jobs = [], []

            for job in all_jobs:
                # Clean job skills
                clean_skills = re.sub(r'[\[\]"]', '', job.required_skills or '')
                job_skills = [s.strip() for s in re.split(r',|\s{2,}|\s(?=[A-Z])', clean_skills) if s.strip()]

                matched_skills, score = calculate_match(user_skills, job_skills)

                job_data = {
                    'job_id': job.id,
                    'title': job.title,
                    'location': job.location,
                    'description_snippet': job.description[:120],
                    'all_skills': job_skills,
                    'matched_skills': matched_skills,
                    'score': score
                }

                # --- Separate lists ---
                if job.id in applied_job_ids:
                    applied_jobs.append(job_data)
                else:
                    recommended_jobs.append(job_data)

            # Sort recommended jobs by match score
            recommended_jobs.sort(key=lambda j: j['score'], reverse=True)

            return render_template(
                "dashboard.html",
                profile=profile,
                applied_jobs=applied_jobs,
                recommended_jobs=recommended_jobs
            )
        except Exception as e:
            flash("Error loading dashboard", "danger")
            print(f"Database error in seeker_dashboard: {e}")
            return redirect(url_for("index"))

    @app.route("/")
    def index():
        try:
            jobs = Job.query.all()
            seekers = User.query.filter_by(role="seeker").all()
            return render_template("index.html", jobs=jobs, seekers=seekers)
        except Exception as e:
            print(f"Database error in index: {e}")
            return render_template("index.html", jobs=[], seekers=[])

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form["email"]
            password = request.form["password"]

            try:
                user = User.query.filter_by(email=email).first()
                if user and check_password_hash(user.password, password):
                    if user.role == "seeker":
                        login_user(user)
                        flash("Logged in successfully!", "success")
                        return redirect(url_for("seeker_dashboard"))
                    elif user.role == "employer":
                        login_user(user)
                        flash("Logged in successfully!", "success")
                        return redirect(url_for("employer_dashboard"))
                else:
                    flash("Invalid credentials", "danger")
                    return redirect(url_for("login"))
            except Exception as e:
                flash("Error during login", "danger")
                print(f"Database error in login: {e}")
                return redirect(url_for("login"))
        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Logged out successfully", "success")
        return redirect(url_for("login"))

    @app.route("/job/<int:job_id>")
    def job_detail(job_id):
        try:
            job = Job.query.get_or_404(job_id)
            return render_template("job.html", job=job)
        except Exception as e:
            flash("Job not found", "danger")
            print(f"Database error in job_detail: {e}")
            return redirect(url_for("seeker_dashboard"))

    # FIXED RECOMMENDATION ROUTE
    @app.route("/api/recommendations/<int:seeker_id>")
    def recommendations(seeker_id):
        try:
            profile = Profile.query.filter_by(user_id=seeker_id).first()
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

            seeker_skills = get_seeker_skills(profile)
            jobs = Job.query.all()
            matches = []

            for job in jobs:
                job_skills = []
                if hasattr(job, "required_skills") and job.required_skills:
                    if isinstance(job.required_skills, str):
                        job_skills = [s.strip().lower() for s in job.required_skills.split(",") if s.strip()]
                    else:
                        job_skills = job.required_skills

                matched_skills = list(set(seeker_skills) & set(job_skills))
                score = len(matched_skills) / len(job_skills) if job_skills else 0

                if score > 0:
                    matches.append({
                        "job_id": job.id,
                        "title": job.title,
                        "description_snippet": job.description[:100],
                        "score": round(score, 4),
                        "matched_skills": matched_skills
                    })

            matches = sorted(matches, key=lambda x: x["score"], reverse=True)
            return jsonify({"matches": matches})
        except Exception as e:
            print(f"Database error in recommendations: {e}")
            return jsonify({"error": "Server error"}), 500

    from flask_mail import Message
    from werkzeug.utils import secure_filename
    import os

    @app.route("/apply/<int:job_id>")
    @login_required
    def apply_job(job_id):
        if current_user.role != "seeker":
            flash("Only seekers can apply!", "warning")
            return redirect(url_for("index"))

        try:
            job = Job.query.get_or_404(job_id)
            employer = User.query.get(job.employer_id)
            applicant_profile = Applicant.query.filter_by(user_id=current_user.id).first()
            profile = Profile.query.filter_by(user_id=current_user.id).first()
            
            if not profile or not profile.resume:
                flash("Please upload your CV before applying.", "warning")
                return redirect(url_for("upload_resume"))

            # Check if already applied
            existing = Application.query.filter_by(job_id=job_id, applicant_id=applicant_profile.id).first()
            if existing:
                flash("Already applied!", "warning")
                return redirect(url_for("seeker_dashboard"))

            # Save application in DB
            app_obj = Application(job_id=job_id,applicant_id=applicant_profile.id, cv_filename=profile.resume)
            db.session.add(app_obj)
            db.session.commit()

            # Send email with CV attached
            try:
                msg = Message(
                    subject=f"New Application for {job.title}",
                    sender=("JobMatch Platform", "no-reply@jobmatch.com"),
                    recipients=[employer.email],
                )
                msg.body = (
                    f"Hello {employer.email},\n\n"
                    f"You have a new application for your job post: {job.title}\n\n"
                    f"Applicant Email: {current_user.email}\n"
                    f"Applicant Name: {profile.full_name}\n"
                    f"Job Location: {job.location}\n\n"
                    "Please find the attached CV for review.\n\n"
                    "Regards,\nJobMatch Team"
                )

                # Attach CV file if exists
                resume_path = os.path.join(app.config["UPLOAD_FOLDER"], profile.resume)
                if os.path.exists(resume_path):
                    with open(resume_path, "rb") as fp:
                        msg.attach(
                            filename=secure_filename(profile.resume),
                            content_type="application/octet-stream",
                            data=fp.read()
                        )

                mail.send(msg)
                flash("Applied successfully and CV sent to employer!", "success")

            except Exception as e:
                print("Email send failed:", e)
                flash("Applied successfully, but email failed to send.", "warning")

            return redirect(url_for("seeker_dashboard"))
        except Exception as e:
            db.session.rollback()
            flash("Error applying for job", "danger")
            print(f"Database error in apply_job: {e}")
            return redirect(url_for("seeker_dashboard"))

    @app.route("/my_applications")
    @login_required
    def my_applications():
        if current_user.role != "seeker":
            flash("Only seekers can view this page.", "warning")
            return redirect(url_for("index"))
        
        try:
            profile = current_user.profile
            applicant_profile = Applicant.query.filter_by(user_id=current_user.id).first()

            applications = (
                Application.query
                .filter_by(applicant_id=applicant_profile.id)
                .join(Job, Application.job_id == Job.id)
                .add_entity(Job)
                .all()
            )

            return render_template("my_applications.html", profile=profile, applications=applications)
        except Exception as e:
            flash("Error loading applications", "danger")
            print(f"Database error in my_applications: {e}")
            return redirect(url_for("seeker_dashboard"))

    @app.route("/withdraw_application/<int:app_id>", methods=["POST"])
    @login_required
    def withdraw_application(app_id):
        """Allow seekers to withdraw their job application."""
        try:
            application = Application.query.get_or_404(app_id)
            applicant_profile = Applicant.query.filter_by(user_id=current_user.id).first()
            # Only the user who applied can withdraw
            if application.applicant_id != applicant_profile.id:
                flash("Unauthorized action.", "danger")
                return redirect(url_for("my_applications"))

            db.session.delete(application)
            db.session.commit()
            flash("You have withdrawn your application.", "success")
            return redirect(url_for("my_applications"))
        except Exception as e:
            db.session.rollback()
            flash("Error withdrawing application", "danger")
            print(f"Database error in withdraw_application: {e}")
            return redirect(url_for("my_applications"))

    @app.route("/employer/applications")
    @login_required
    def employer_applications():
        if current_user.role != "employer":
            flash("Only employers can view applications.", "warning")
            return redirect(url_for("index"))

        try:
            jobs = Job.query.filter_by(employer_id=current_user.id).all()
            job_ids = [job.id for job in jobs]

            applications = (
                Application.query
                .filter(Application.job_id.in_(job_ids))
                .join(Job)
                .join(User, Application.applicant_id == User.id)
                .join(Profile, Profile.user_id == User.id)
                .add_entity(Job)
                .add_entity(Profile)
                .all()
            )

            return render_template("employer_applications.html", applications=applications)
        except Exception as e:
            flash("Error loading applications", "danger")
            print(f"Database error in employer_applications: {e}")
            return redirect(url_for("employer_dashboard"))

    # --- WTForms for Profile Creation ---
    class ProfileForm(FlaskForm):
        full_name = StringField("Full Name", validators=[DataRequired(), Length(max=100)])
        bio = TextAreaField("Bio")
        experience_years = DecimalField("Experience Years", validators=[NumberRange(min=0)], places=1)  
        skills = StringField("Skills")
        resume_text = TextAreaField("Resume Text")  
        submit = SubmitField("Save Profile")

    @app.route("/create_profile", methods=["POST", "GET"])
    def create_profile():
        if current_user.role != "seeker":
            flash("Only registered applicants can add details.", "warning")
            return redirect(url_for("login"))
        
        form = ProfileForm()

        if form.validate_on_submit():
            try:
                skills_raw = request.form.get("skills", "")
                skills_cleaned = [s.strip() for s in skills_raw.split(",") if s.strip()]
                skills_str = ", ".join(skills_cleaned)

                profile = Profile(
                    user_id = current_user.id,
                    full_name = form.full_name.data,
                    bio = form.bio.data,
                    skills = skills_str,
                    experience_years = float(form.experience_years.data or 0),
                    resume_text = form.resume_text.data or ""
                )
                db.session.add(profile)
                db.session.commit()
                flash("Profile created successfully!", "success")
                return redirect(url_for("seeker_dashboard"))
            except Exception as e:
                db.session.rollback()
                flash("Error creating profile", "danger")
                print(f"Database error in create_profile: {e}")
        return render_template("create_profile.html", form=form, current_user=current_user)

    @app.route("/update_profile/<int:profile_id>", methods=["GET", "POST"])
    @login_required
    def update_applicant_profile(profile_id):
        if current_user.role != "seeker":
            flash("Only registered applicants can edit their profile", "warning")
            return redirect(url_for("seeker_dashboard"))
        
        try:
            profile = Profile.query.filter_by(id=profile_id, user_id=current_user.id).first_or_404()
            user = User.query.filter_by(id=current_user.id).first_or_404()

            form = ProfileForm(obj=profile)

            if form.validate_on_submit():
                try:
                    skills_raw = request.form.get("skills", "")
                    skills_cleaned = [s.strip() for s in skills_raw.split(",") if s.strip()]
                    skills_str = ", ".join(skills_cleaned)

                    profile.full_name = form.full_name.data
                    profile.bio = form.bio.data
                    profile.user.email = request.form.get("email")
                    profile.skills = skills_str
                    profile.experience_years = float(form.experience_years.data or 0)
                    profile.resume_text = form.resume_text.data or ""

                    db.session.commit()
                    flash("Your profile has been successfully updated.", "success")
                    return redirect(url_for("seeker_dashboard"))
                except Exception as e:
                    db.session.rollback()
                    flash("Error updating profile", "danger")
                    print(f"Database error in update_applicant_profile: {e}")

            skills_string = profile.skills or ""
            
            return render_template("update_profile.html", user=user, profile=profile, form=form, skills_string=skills_string)
        except Exception as e:
            flash("Error loading profile", "danger")
            print(f"Database error loading profile: {e}")
            return redirect(url_for("seeker_dashboard"))

    @app.route("/employer_dashboard")
    @login_required
    def employer_dashboard():
        if current_user.role != "employer":
            flash("Only employers can access this dashboard.", "warning")
            return redirect(url_for("index"))
        
        try:
            employer_profile = Employer.query.filter_by(user_id=current_user.id).first()
            if not employer_profile:
                flash("Please complete your registration first.", "warning")
                return redirect(url_for("register"))

            # Fetch all jobs created by the employer
            jobs = Job.query.filter_by(employer_id=current_user.id).all()

            # Count applicants per job
            job_data = []
            for job in jobs:
                applicants_count = Application.query.filter_by(job_id=job.id).count()
                job_data.append({
                    "job": job,
                    "applicants_count": applicants_count
                })

            return render_template("employer_dashboard.html", employer_profile=employer_profile, jobs=job_data)
        except Exception as e:
            flash("Error loading dashboard", "danger")
            print(f"Database error in employer_dashboard: {e}")
            return redirect(url_for("index"))

    # --- WTForms for Employee Profile/Update Creation ---
    class CreateUpdateEmployerForm(FlaskForm):
        company_name = StringField("Company Name", validators=[DataRequired(), Length(max=200)])
        company_email = StringField("Company Email", validators=[DataRequired()])
        phone_number = StringField("Phone Number")
        address = TextAreaField("Address")  
        industry = StringField("Industry")  
        submit = SubmitField("Save Profile")

    @app.route("/create_employer_profile")
    def create_employer_profile():
        if current_user != "employer":
            flash("Only registered and verified employers can add details", "warning")
            return redirect(url_for("login"))
        
        form = CreateUpdateEmployerForm()

        if form.validate_on_submit():
            try:
                industry_raw = request.form.get("industry", "")
                industry_cleaned = [s.strip() for s in industry_raw.split(",") if s.strip()]
                industry_str = ", ".join(industry_cleaned)

                profile = Profile(
                    user_id = current_user.id,
                    company_name = form.company_name.data,
                    company_email = form.company_email.data,
                    phone_number = form.phone_number.data,
                    address = form.address.data,
                    industry = industry_str
                )

                db.session.add(profile)
                db.session.commit()
                flash("Profile created successfully.", "success")
                return redirect(url_for("employer_dashboard"))
            except Exception as e:
                db.session.rollback()
                flash("Error creating employer profile", "danger")
                print(f"Database error in create_employer_profile: {e}")
        return render_template("create_employer_profile.html", form=form, current_user=current_user)

    @app.route("/update_employer_profile/<int:employer_id>", methods=["GET", "POST"])
    @login_required
    def update_employer_profile(employer_id):
        if current_user.role != "employer":
            flash("Only registered employers can edit.", "warning")
            return redirect(url_for("employer_dashboard"))
        
        try:
            employer = Employer.query.filter_by(id=employer_id, user_id=current_user.id).first_or_404()

            form = CreateUpdateEmployerForm(obj = employer)

            if form.validate_on_submit():
                try:
                    industry_raw = request.form.get("industry", "")
                    industry_cleaned = [s.strip() for s in industry_raw.split(",") if s.strip()]
                    industry_str = ", ".join(industry_cleaned)

                    employer.company_name = form.company_name.data
                    employer.company_email = form.company_email.data
                    employer.phone_number = form.phone_number.data
                    employer.address = form.address.data
                    employer.industry = industry_str

                    db.session.commit()
                    flash("Your profile has been successfully updated.", "success")
                    return redirect(url_for("employer_dashboard"))
                except Exception as e:
                    db.session.rollback()
                    flash("Error updating employer profile", "danger")
                    print(f"Database error in update_employer_profile: {e}")
        
            industry_string = employer.industry or ""

            return render_template("update_employer_profile.html", form=form, employer=employer, industry_string=industry_string)
        except Exception as e:
            flash("Error loading employer profile", "danger")
            print(f"Database error loading employer profile: {e}")
            return redirect(url_for("employer_dashboard"))

    @app.route("/job/<int:job_id>/applicants")
    @login_required
    def view_applicants(job_id):
        # Make sure only employers can see their job applicants
        if current_user.role != "employer":
            flash("Only employers can view applicants.", "warning")
            return redirect(url_for("index"))

        try:
            # Get the job, make sure it belongs to the current employer
            job = Job.query.filter_by(id=job_id, employer_id=current_user.id).first_or_404()

            recommended_jobs = job

            # Get all applications for this job
            applications = Application.query.filter_by(job_id=job.id).all()

            for app in applications:
                if isinstance(app.interview_date, str):
                    try:
                        app.interview_date = datetime.fromisoformat(app.interview_date)
                    except ValueError:
                        app.interview_date = None

            return render_template("view_applicants.html", recommended_jobs=recommended_jobs, job=job, applications=applications)
        except Exception as e:
            flash("Error loading applicants", "danger")
            print(f"Database error in view_applicants: {e}")
            return redirect(url_for("employer_dashboard"))

    @app.route("/application/<int:app_id>/status/<status>")
    @login_required
    def update_application_status(app_id, status):
        try:
            application = Application.query.get_or_404(app_id)
            if current_user.role != "employer":
                flash("Unauthorized", "danger")
                return redirect(url_for("index"))

            application.status = status
            db.session.commit()
            flash(f"Application status updated to {status}", "success")
            return redirect(request.referrer)
        except Exception as e:
            db.session.rollback()
            flash("Error updating application status", "danger")
            print(f"Database error in update_application_status: {e}")
            return redirect(request.referrer)

    # =========================================================================

    # --- WTForms for Job Creation ---
    class JobForm(FlaskForm):
        title = StringField("Job Title", validators=[DataRequired(), Length(max=100)])
        description = TextAreaField("Job Description", validators=[DataRequired()])
        location = StringField("Location", validators=[DataRequired(), Length(max=100)])
        salary = StringField("Salary (USD)")
        job_type = SelectField("Job Type", choices=[("full-time","Full Time"), ("part-time","Part Time"), ("contract","Contract")], validators=[DataRequired()])
        submit = SubmitField("Post Job")

    from datetime import datetime

    @app.route("/application/<int:app_id>/schedule_interview", methods=["POST"])
    @login_required
    def schedule_interview(app_id):
        if current_user.role != "employer":
            flash("Unauthorized", "danger")
            return redirect(url_for("index"))

        try:
            application = Application.query.get_or_404(app_id)
            employer = Employer.query.filter_by(user_id=current_user.id).first()
            # Parse date and time from form
            date_str = request.form.get("interview_date")
            time_str = request.form.get("interview_time")
            interview_type = request.form.get("interview_type")
            
            if not date_str or not time_str:
                flash("Please provide both date and time", "danger")
                return redirect(request.referrer)

            # Combine date and time into datetime
            interview_datetime = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")

            application.status = "Interview"
            application.interview_date = interview_datetime
            application.interview_type = interview_type
            db.session.commit()

            # Notify applicant via email
            try:
                msg = Message(
                    subject=f"Interview Scheduled for {application.job.title}",
                    sender=app.config['MAIL_DEFAULT_SENDER'],
                    recipients=[application.applicant.user.email],
                )
                msg.body = (
                    f"Hello {application.applicant.full_name},\n\n"
                    f"Your interview for '{application.job.title}' has been scheduled.\n\n"
                    f"📅 Date & Time: {interview_datetime.strftime('%B %d, %Y at %I:%M %p')}\n"
                    f"🏢 Company Name: {employer.company_name or 'Company XYZ'}\n"
                    f"🤝 Type of interview: {application.interview_type}\n\n"
                    "Please make sure to attend on time.\n\n"
                    "Best regards,\nLastBit Job Platform Team"
                )
                mail.send(msg)
                flash("Interview scheduled and applicant notified via email!", "success")

            except Exception as e:
                print("❌ Email send failed:", e)
                flash(f"Interview scheduled, but email failed to send: {e}", "warning")

            flash("Interview scheduled and applicant notified!", "success")
            return redirect(request.referrer)
        except Exception as e:
            db.session.rollback()
            flash("Error scheduling interview", "danger")
            print(f"Database error in schedule_interview: {e}")
            return redirect(request.referrer)

    # --- Route to create job ---
    @app.route("/create_job", methods=["GET", "POST"])
    @login_required
    def create_job():
        if current_user.role != "employer":
            flash("Only employers can create jobs.", "warning")
            return redirect(url_for("index"))

        form = JobForm()
        salary_value = form.salary.data
        if isinstance(salary_value, Decimal):
            salary_value = float(salary_value)

        if form.validate_on_submit():
            try:
                skills_raw = request.form.get("skills", "")
                skills_cleaned = [s.strip() for s in skills_raw.split(",") if s.strip()]
                skills_json = ", ".join(skills_cleaned)  
                
                job = Job(
                    title=form.title.data,
                    description=form.description.data,
                    location=form.location.data,
                    salary=salary_value,
                    job_type=form.job_type.data,
                    employer_id=current_user.id,
                    required_skills=skills_json
                )
                db.session.add(job)
                db.session.commit()
                flash("Job posted successfully!", "success")
                return redirect(url_for("employer_dashboard"))
            except Exception as e:
                db.session.rollback()
                flash(f"Database error: {str(e)}", "danger")
                print(f"Database exception: {e}")

        return render_template("create_job.html", form=form, current_user=current_user)

    # ============= Update Job =============

    @app.route("/update_job/<int:job_id>", methods=["GET", "POST"])
    @login_required
    def update_job(job_id):
        if current_user.role != "employer":
            flash("Only employers can edit jobs.", "warning")
            return redirect(url_for("index"))

        try:
            # Fetch the job to edit
            job = Job.query.filter_by(id=job_id, employer_id=current_user.id).first_or_404()

            form = JobForm(obj=job)  # pre-fill form with existing data

            if form.validate_on_submit():
                try:
                    # Update job fields from form
                    job.title = form.title.data
                    job.description = form.description.data
                    job.location = form.location.data
                    job.salary = float(form.salary.data) if form.salary.data else None
                    job.job_type = form.job_type.data

                    # Process skills input
                    skills_raw = request.form.get("skills", "")
                    skills_cleaned = [s.strip() for s in skills_raw.split(",") if s.strip()]
                    skills_str = ", ".join(skills_cleaned)

                    db.session.commit()
                    flash("Job post updated successfully!", "success")
                    return redirect(url_for("employer_dashboard"))
                except Exception as e:
                    db.session.rollback()
                    flash("Error updating job", "danger")
                    print(f"Database error updating job: {e}")

            # Pre-fill skills input field as comma-separated string
            skills_string = job.required_skills or ""

            return render_template(
                "update_job.html",
                job=job,
                form=form,
                skills_string=skills_string
            )
        except Exception as e:
            flash("Error loading job", "danger")
            print(f"Database error loading job: {e}")
            return redirect(url_for("employer_dashboard"))

    @app.route("/delete_job/<int:job_id>", methods=["POST"])
    @login_required
    def delete_job(job_id):
        if current_user.role != "employer":
            flash("Unauthorized access.", "danger")
            return redirect(url_for("index"))

        try:
            job = Job.query.filter_by(id=job_id, employer_id=current_user.id).first_or_404()

            # Delete related applications first (cascade alternative)
            Application.query.filter_by(job_id=job.id).delete()

            db.session.delete(job)
            db.session.commit()
            flash("Job post removed successfully!", "success")
            return redirect(url_for("employer_dashboard"))
        except Exception as e:
            db.session.rollback()
            flash("Error deleting job", "danger")
            print(f"Database error in delete_job: {e}")
            return redirect(url_for("employer_dashboard"))

    from itsdangerous import URLSafeTimedSerializer
    from flask import current_app

    # Generate verification token
    def generate_token(email):
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        return serializer.dumps(email, salt='email-confirm')

    # Confirm verification token
    def confirm_token(token, expiration=3600):
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            email = serializer.loads(token, salt='email-confirm', max_age=expiration)
        except Exception:
            return False
        return email

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            email = request.form["email"]
            password = generate_password_hash(request.form["password"])
            role = request.form["role"]  # 'applicant' or 'employer'

            try:
                user = User(email=email, password=password, role=role)
                db.session.add(user)
                db.session.commit()

                # Create corresponding profile
                if role == "seeker":
                    db.session.add(Applicant(user_id=user.id, full_name=request.form.get("full_name", "")))
                else:
                    db.session.add(Employer(user_id=user.id, company_name=request.form.get("company_name", "")))
                db.session.commit()

                # Send verification email
                token = generate_token(user.email)
                verify_url = url_for("verify_email", token=token, _external=True)
                msg = Message(
                    subject="Verify Your Account",
                    sender=current_app.config["MAIL_DEFAULT_SENDER"],
                    recipients=[user.email],
                )
                msg.body = f"Hello!\n\nPlease verify your email by clicking this link:\n{verify_url}\n\nThis link expires in 1 hour."
                mail.send(msg)

                flash("Registration successful! Please check your email to verify your account.", "info")
                return redirect(url_for("login"))
            except Exception as e:
                db.session.rollback()
                flash("Error during registration", "danger")
                print(f"Database error in register: {e}")
                return redirect(url_for("register"))

        return render_template("register.html")


    @app.route("/verify/<token>")
    def verify_email(token):
        email = confirm_token(token)
        if not email:
            flash("The verification link is invalid or has expired.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Account not found.", "danger")
            return redirect(url_for("login"))

        if user.is_verified:
            flash("Account already verified. Please log in.", "info")
        else:
            user.is_verified = True
            db.session.commit()
            flash("Your email has been verified! You can now log in.", "success")

        return redirect(url_for("login"))

   
    return app


# if __name__ == "__main__":
#     app = create_app()
#     # app.run(debug=True)

#     if IS_PRODUCTION:
#         # For production, use Waitress instead
#         from waitress import serve
#         print("Starting production server on http://0.0.0.0:8080")
#         serve(app, host='0.0.0.0', port=8080)
#     else:
#         app.run(debug=True, host='127.0.0.1', port=5000)
# Remove the Waitress import and conditional block, replace with:
if __name__ == "__main__":
    app = create_app()
    app.run(debug=not IS_PRODUCTION, host='0.0.0.0' if IS_PRODUCTION else '127.0.0.1', port=5000)