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
from wtforms import StringField, EmailField, TextAreaField, SelectField, DecimalField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, NumberRange
from decimal import Decimal
from flask_sqlalchemy import SQLAlchemy

from forms import (
    Step1RegistrationForm, Step2SeekerBasicForm, Step3SeekerSkillsForm, 
    Step4SeekerBioForm, Step2EmployerBasicForm, Step3EmployerLocationForm, 
    Step4EmployerIndustryForm, CompleteRegistrationForm, LoginForm,
    JobForm, ProfileUpdateForm, EmployerProfileUpdateForm
)
from markupsafe import Markup
from datetime import datetime
import pytz

from dotenv import load_dotenv
load_dotenv()

migrate = Migrate()
csrf = CSRFProtect()


def create_app():
    import os
    app = Flask(__name__)

    def get_zimbabwe_time():
        """Get current datetime in Zimbabwe timezone"""
        zimbabwe_tz = pytz.timezone('Africa/Harare')
        return datetime.now(zimbabwe_tz)

    # Or for converting UTC to Zimbabwe time
    def utc_to_zimbabwe(utc_dt):
        """Convert UTC datetime to Zimbabwe time"""
        if utc_dt.tzinfo is None:
            utc_dt = pytz.utc.localize(utc_dt)
        zimbabwe_tz = pytz.timezone('Africa/Harare')
        return utc_dt.astimezone(zimbabwe_tz)

    # Production Configuration
    if IS_PRODUCTION:
        # app.config["ENV"] = "production"
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
            
            # Get employer from Employer table, not User table
            employer = Employer.query.get(job.employer_id)
            if not employer:
                flash("Employer not found.", "danger")
                return redirect(url_for("seeker_dashboard"))
                
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
            app_obj = Application(job_id=job_id, applicant_id=applicant_profile.id, cv_filename=profile.resume)
            db.session.add(app_obj)
            
            # Update job applications count
            job.applications_count += 1
            
            db.session.commit()

            # Send email with CV attached
            try:
                # Use company_email if available, otherwise fall back to user email
                recipient_email = employer.user.email
                
                msg = Message(
                    subject=f"New Application for {job.title}",
                    sender=("LastBit Job Platform", app.config["MAIL_USERNAME"]),
                    recipients=[recipient_email],
                )
                msg.body = (
                    f"Hello {employer.company_name or 'Employer'},\n\n"
                    f"You have a new application for your job post: {job.title}\n\n"
                    f"Applicant Name: {profile.full_name}\n"
                    f"Applicant Email: {current_user.email}\n"
                    f"Job Location: {job.location}\n"
                    f"Job Type: {job.job_type}\n\n"
                    f"Applicant Skills: {profile.skills or 'Not specified'}\n"
                    f"Years of Experience: {profile.years_experience or 'Not specified'}\n\n"
                    "Please find the attached CV for review.\n\n"
                    "You can view all applications in your employer dashboard.\n\n"
                    "Regards,\nLastBit Job Platform Team"
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
                print(f"DEBUG: Email sent to: {recipient_email}")
                print(f"DEBUG: Employer company email: {employer.company_email}")
                print(f"DEBUG: Employer user email: {employer.user.email}")
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

    #    # --- WTForms for Profile Creation ---
    class ProfileForm(FlaskForm):
        full_name = StringField("Full Name", validators=[DataRequired(), Length(max=100)])
        bio = TextAreaField("Bio")
        experience_years = DecimalField("Experience Years", validators=[NumberRange(min=0)], places=1)  
        skills = StringField("Skills")
        resume_text = TextAreaField("Resume Text")  
        submit = SubmitField("Save Profile")

    # Update create_profile route
    @app.route("/create_profile", methods=["GET", "POST"])
    @login_required
    def create_profile():
        if current_user.role != "seeker":
            flash("Only job seekers can create profiles.", "warning")
            return redirect(url_for("index"))
        
        # Check if profile already exists
        existing_profile = Profile.query.filter_by(user_id=current_user.id).first()
        if existing_profile:
            flash("Profile already exists. You can update it instead.", "info")
            return redirect(url_for("update_applicant_profile", profile_id=existing_profile.id))
        
        form = ProfileUpdateForm()
        
        if form.validate_on_submit():
            try:
                # Create Profile
                profile = Profile(
                    user_id=current_user.id,
                    full_name=form.full_name.data,
                    phone=form.phone.data,
                    city=form.city.data,
                    country=form.country.data,
                    current_job_title=form.current_job_title.data,
                    current_company=form.current_company.data,
                    years_experience=float(form.years_experience.data or 0),
                    notice_period=form.notice_period.data,
                    education_level=form.education_level.data,
                    field_of_study=form.field_of_study.data,
                    university=form.university.data,
                    graduation_year=form.graduation_year.data,
                    skills=form.skills.data,
                    bio=form.bio.data,
                    expected_salary=form.expected_salary.data,
                    preferred_job_types=form.preferred_job_types.data,
                    preferred_locations=form.preferred_locations.data,
                    remote_preference=form.remote_preference.data,
                    linkedin_url=form.linkedin_url.data,
                    github_url=form.github_url.data,
                    portfolio_url=form.portfolio_url.data
                )
                
                db.session.add(profile)
                
                # Update user's profile completion
                current_user.profile_completion = profile.calculate_profile_completion()
                
                db.session.commit()
                
                flash("Profile created successfully!", "success")
                return redirect(url_for("seeker_dashboard"))
                
            except Exception as e:
                db.session.rollback()
                flash(f"Error creating profile: {str(e)}", "danger")
                print(f"Database error in create_profile: {e}")
        
        # Calculate initial completion for display
        profile_completion = 0
        
        return render_template("create_profile.html", 
                            form=form, 
                            current_user=current_user,
                            profile_completion=profile_completion)

    # Update update_applicant_profile route
    @app.route("/update_profile/<int:profile_id>", methods=["GET", "POST"])
    @login_required
    def update_applicant_profile(profile_id):
        if current_user.role != "seeker":
            flash("Only job seekers can update profiles.", "warning")
            return redirect(url_for("index"))
        
        try:
            profile = Profile.query.filter_by(id=profile_id, user_id=current_user.id).first_or_404()
            user = User.query.get(current_user.id)
            
            form = ProfileUpdateForm(obj=profile)
            
            if form.validate_on_submit():
                try:
                    # Update profile fields
                    profile.full_name = form.full_name.data
                    profile.phone = form.phone.data
                    profile.city = form.city.data
                    profile.country = form.country.data
                    profile.current_job_title = form.current_job_title.data
                    profile.current_company = form.current_company.data
                    profile.years_experience = float(form.years_experience.data or 0)
                    profile.notice_period = form.notice_period.data
                    profile.education_level = form.education_level.data
                    profile.field_of_study = form.field_of_study.data
                    profile.university = form.university.data
                    profile.graduation_year = form.graduation_year.data
                    profile.skills = form.skills.data
                    profile.bio = form.bio.data
                    profile.expected_salary = form.expected_salary.data
                    profile.preferred_job_types = form.preferred_job_types.data
                    profile.preferred_locations = form.preferred_locations.data
                    profile.remote_preference = form.remote_preference.data
                    profile.linkedin_url = form.linkedin_url.data
                    profile.github_url = form.github_url.data
                    profile.portfolio_url = form.portfolio_url.data
                    
                    # Update user email if changed
                    new_email = request.form.get("email")
                    if new_email and new_email != user.email:
                        # Check if email is already taken
                        existing_user = User.query.filter_by(email=new_email).first()
                        if existing_user and existing_user.id != user.id:
                            flash("Email already registered by another user.", "danger")
                        else:
                            user.email = new_email
                    
                    # Update profile completion
                    user.profile_completion = profile.calculate_profile_completion()
                    
                    db.session.commit()
                    flash("Your profile has been updated successfully.", "success")
                    return redirect(url_for("seeker_dashboard"))
                    
                except Exception as e:
                    db.session.rollback()
                    flash(f"Error updating profile: {str(e)}", "danger")
                    print(f"Database error in update_applicant_profile: {e}")
            
            # Calculate current completion for display
            profile_completion = profile.calculate_profile_completion()
            
            return render_template("update_profile.html", 
                                user=user, 
                                profile=profile, 
                                form=form,
                                profile_completion=profile_completion)
            
        except Exception as e:
            flash("Error loading profile", "danger")
            print(f"Database error loading profile: {e}")
            return redirect(url_for("seeker_dashboard"))

    import time

    # Update create_job route
    @app.route("/create_job", methods=["GET", "POST"])
    @login_required
    def create_job():
        if current_user.role != "employer":
            flash("Only employers can create jobs.", "warning")
            return redirect(url_for("index"))
        
        form = JobForm()
        
        if form.validate_on_submit():
            try:
                # Get employer profile
                employer = Employer.query.filter_by(user_id=current_user.id).first()
                if not employer:
                    flash("Please complete your employer profile first.", "warning")
                    return redirect(url_for("create_employer_profile"))
                
                # Generate job code
                job_code = f"JOB-{current_user.id}-{int(time.time())}"
                
                job = Job(
                    title=form.title.data,
                    job_code=job_code,
                    department=form.department.data,
                    description=form.description.data,
                    responsibilities=form.responsibilities.data,
                    requirements=form.requirements.data,
                    benefits=form.benefits.data,
                    salary_min=form.salary_min.data,
                    salary_max=form.salary_max.data,
                    salary_currency=form.salary_currency.data,
                    
                    location=form.location.data,
                    location_type=form.location_type.data,
                    
                    job_type=form.job_type.data,
                    work_schedule=form.work_schedule.data,
                    experience_min=form.experience_min.data,
                    experience_max=form.experience_max.data,
                    education_required=form.education_required.data,
                    required_skills=form.required_skills.data,
                    preferred_skills=form.preferred_skills.data,
                    
                    application_deadline=form.application_deadline.data,
                    status=form.status.data,
                    is_featured=form.is_featured.data,
                    is_urgent=form.is_urgent.data,
                    employer_id=employer.id,
                )
                
                db.session.add(job)
                
                # Update employer stats
                employer.total_jobs_posted += 1
                
                db.session.commit()
                
                flash("Job posted successfully!", "success")
                return redirect(url_for("employer_dashboard"))
                
            except Exception as e:
                db.session.rollback()
                flash(f"Error creating job: {str(e)}", "danger")
                print(f"Database error in create_job: {e}")
        
        return render_template("create_job.html", 
                            form=form, 
                            current_user=current_user)

    # Update update_job route
    @app.route("/update_job/<int:job_id>", methods=["GET", "POST"])
    @login_required
    def update_job(job_id):
        if current_user.role != "employer":
            flash("Only employers can edit jobs.", "warning")
            return redirect(url_for("index"))
        
        try:
            # Get employer profile
            employer = Employer.query.filter_by(user_id=current_user.id).first()
            if not employer:
                flash("Employer profile not found.", "danger")
                return redirect(url_for("employer_dashboard"))
            
            # Fetch the job to edit
            job = Job.query.filter_by(id=job_id, employer_id=employer.id).first_or_404()
            
            form = JobForm(obj=job)
            
            if form.validate_on_submit():
                try:
                    # Update job fields
                    job.title = form.title.data
                    job.department = form.department.data
                    job.description = form.description.data
                    job.responsibilities = form.responsibilities.data
                    job.requirements = form.requirements.data
                    job.benefits = form.benefits.data
                    job.salary_min = form.salary_min.data
                    job.salary_max = form.salary_max.data
                    job.salary_currency = form.salary_currency.data
                    job.bonus_potential = form.bonus_potential.data
                    job.location = form.location.data
                    job.location_type = form.location_type.data
                    job.address = form.address.data
                    job.job_type = form.job_type.data
                    job.work_schedule = form.work_schedule.data
                    job.experience_min = form.experience_min.data
                    job.experience_max = form.experience_max.data
                    job.education_required = form.education_required.data
                    job.required_skills = form.required_skills.data
                    job.preferred_skills = form.preferred_skills.data
                    job.certifications = form.certifications.data
                    job.application_deadline = form.application_deadline.data
                    job.hiring_contact = form.hiring_contact.data
                    job.hiring_contact_email = form.hiring_contact_email.data
                    job.status = form.status.data
                    job.is_featured = form.is_featured.data
                    job.is_urgent = form.is_urgent.data
                    job.updated_at = datetime.utcnow()
                    
                    db.session.commit()
                    flash("Job updated successfully!", "success")
                    return redirect(url_for("employer_dashboard"))
                    
                except Exception as e:
                    db.session.rollback()
                    flash(f"Error updating job: {str(e)}", "danger")
                    print(f"Database error updating job: {e}")
            
            return render_template("update_job.html",
                                job=job,
                                form=form)
            
        except Exception as e:
            flash("Error loading job", "danger")
            print(f"Database error loading job: {e}")
            return redirect(url_for("employer_dashboard"))

    @app.route("/employer_dashboard")
    @login_required
    def employer_dashboard():
        if current_user.role != "employer":
            flash("Only employers can access this dashboard.", "warning")
            return redirect(url_for("index"))
        
        try:
            print("=== DEBUG: Starting employer_dashboard ===")
            
            employer_profile = Employer.query.filter_by(user_id=current_user.id).first()
            if not employer_profile:
                flash("Please complete your registration first.", "warning")
                return redirect(url_for("register"))
            
            print(f"1. Found employer profile: {employer_profile.company_name}")
            
            # Calculate profile completion for employer
            def calculate_employer_profile_completion(employer):
                """Calculate employer profile completion percentage"""
                print(f"2. Calculating profile completion for employer: {employer.id}")
                
                required_fields = [
                    employer.company_name,
                    employer.company_email,
                    employer.company_phone,
                    employer.industry,
                    employer.description,
                    employer.website,
                    employer.address,
                    employer.city,
                    employer.country
                ]
                
                # Debug each field
                for i, field in enumerate(required_fields):
                    print(f"   Field {i}: {field} (type: {type(field)})")
                
                # Count completed fields
                completed = 0
                for field in required_fields:
                    if field and str(field).strip():
                        completed += 1
                
                print(f"   Completed: {completed} out of {len(required_fields)}")
                
                percentage = int((completed / len(required_fields)) * 100) if required_fields else 0
                print(f"   Percentage: {percentage}%")
                
                return percentage
            
            try:
                profile_completion = calculate_employer_profile_completion(employer_profile)
                print(f"3. Profile completion calculated: {profile_completion}%")
            except Exception as e:
                print(f"Error calculating profile completion: {e}")
                profile_completion = 0
            
            # Update user's profile completion in database
            try:
                if current_user.profile_completion != profile_completion:
                    current_user.profile_completion = profile_completion
                    db.session.commit()
                    print(f"4. Updated user profile completion to: {profile_completion}%")
            except Exception as e:
                print(f"Error updating profile completion in DB: {e}")
                db.session.rollback()
            
            # Fetch all jobs created by the employer
            jobs = Job.query.filter_by(employer_id=employer_profile.id).all()
            print(f"5. Found {len(jobs)} jobs for employer")
            
            # Count applicants per job
            job_data = []
            total_applications = 0
            
            for job in jobs:
                applicants_count = Application.query.filter_by(job_id=job.id).count()
                total_applications += applicants_count
                job_data.append({
                    "job": job,
                    "applicants_count": applicants_count
                })
            
            print(f"6. Total applications across all jobs: {total_applications}")

            # Get recent applications (last 4)
            recent_applications = []
            try:
                recent_applications = Application.query \
                    .join(Job, Application.job_id == Job.id) \
                    .filter(Job.employer_id == employer_profile.id) \
                    .order_by(Application.created_at.desc()) \
                    .limit(4) \
                    .all()
                print(f"7. Found {len(recent_applications)} recent applications")
            except Exception as e:
                print(f"Error fetching recent applications: {e}")
            
            # Handle profile_views - check if it's an integer or list
            profile_views = 0
            try:
                # If you're passing a list in the template
                profile_views_list = []  # Replace with your actual query if you have a ProfileViews model
                # profile_views_list = ProfileView.query.filter_by(employer_id=employer_profile.id).all()
                
                # If employer_profile has views_count attribute
                if hasattr(employer_profile, 'views_count'):
                    profile_views = employer_profile.views_count or 0
                else:
                    profile_views = 0
                    
                print(f"8. Profile views: {profile_views}")
            except Exception as e:
                print(f"Error handling profile views: {e}")
            
            print("=== DEBUG: Rendering template ===")
            
            return render_template(
                "employer_dashboard.html",
                employer_profile=employer_profile,
                job_data=job_data,
                total_applications=total_applications,
                recent_applications=recent_applications,
                profile_views=profile_views,  # Pass as integer
                profile_completion=profile_completion
            )
            
        except Exception as e:
            flash("Error loading dashboard", "danger")
            print(f"=== DEBUG: ERROR in employer_dashboard: {e} ===")
            import traceback
            traceback.print_exc()
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
        
        existing_company = Employer.query.filter_by(user_id = current_user.id).first()
        if existing_company:
            flash("Profile already exists. You can update it instead.", "info")
            return redirect(url_for("update_employer_profile", employer_id=existing_company.id))
        
        form = CreateUpdateEmployerForm()

        if form.validate_on_submit():
            try:
                industry_raw = request.form.get("industry", "")
                industry_cleaned = [s.strip() for s in industry_raw.split(",") if s.strip()]
                industry_str = ", ".join(industry_cleaned)

                # profile = Profile(
                #     user_id = current_user.id,
                #     company_name = form.company_name.data,
                #     company_email = form.company_email.data,
                #     phone_number = form.phone_number.data,
                #     address = form.address.data,
                #     industry = industry_str
                # )
                employer = Employer(
                    user_id = current_user.id,
                    company_name = form.company_name.data,
                    company_email = form.company_email.data,
                    company_phone = form.company_phone.data,
                    company_size = form.company_size.data,
                    founded_year = form.founded_year.data,
                    company_type = form.company_type.data,
                    address = form.address.data,
                    city = form.city.data,
                    state = form.state.data,
                    country = form.country.data,
                    zip_code = form.zip_code.data,
                    industry = form.industry.data,
                    sector = form.sector.data,
                    description = form.description.data,
                    website = form.website.data,
                    linkedin_url = form.linkedin_url.data,
                    x_url = form.x_url.data
                )


                db.session.add(employer)

                db.session.commit()
                flash("Profile created successfully.", "success")
                return redirect(url_for("employer_dashboard"))
            except Exception as e:
                db.session.rollback()
                flash("Error creating employer profile", "danger")
                print(f"Database error in create_employer_profile: {e}")

        profile_completion = 0

        return render_template("create_employer_profile.html", form=form, current_user=current_user, profile_completion=profile_completion)

    @app.route("/update_employer_profile/<int:employer_id>", methods=["GET", "POST"])
    @login_required
    def update_employer_profile(employer_id):
        if current_user.role != "employer":
            flash("Only registered employers can edit.", "warning")
            return redirect(url_for("employer_dashboard"))
        
        try:
            employer = Employer.query.filter_by(id=employer_id, user_id=current_user.id).first_or_404()
            form = EmployerProfileUpdateForm(obj=employer)

            # Calculate profile completion percentage
            def calculate_employer_profile_completion(employer):
                """Calculate employer profile completion percentage"""
                required_fields = [
                    employer.company_name,
                    employer.company_email,
                    employer.company_phone,
                    employer.industry,
                    employer.description,
                    employer.website,
                    employer.address,
                    employer.city,
                    employer.country
                ]
                
                completed = sum(1 for field in required_fields if field and str(field).strip())
                percentage = int((completed / len(required_fields)) * 100) if required_fields else 0
                return percentage

            # Calculate completion percentage
            profile_completion = calculate_employer_profile_completion(employer)
            
            # Update user's profile completion if needed
            current_user.profile_completion = profile_completion
            db.session.commit()

            if form.validate_on_submit():
                try:
                    industry_raw = request.form.get("industry", "")
                    industry_cleaned = [s.strip() for s in industry_raw.split(",") if s.strip()]
                    industry_str = ", ".join(industry_cleaned)

                    # Update employer fields
                    employer.company_name = form.company_name.data
                    employer.company_email = form.company_email.data
                    employer.company_phone = form.company_phone.data
                    employer.address = form.address.data
                    employer.industry = industry_str
                    employer.city = form.city.data
                    employer.state = form.state.data
                    employer.country = form.country.data
                    employer.zip_code = form.zip_code.data
                    employer.company_size = form.company_size.data
                    employer.company_type = form.company_type.data
                    employer.founded_year = form.founded_year.data
                    employer.sector = form.sector.data
                    employer.description = form.description.data
                    employer.website = form.website.data
                    employer.linkedin_url = form.linkedin_url.data
                    employer.x_url = form.x_url.data
                    
                    # Recalculate profile completion after update
                    new_profile_completion = calculate_employer_profile_completion(employer)
                    current_user.profile_completion = new_profile_completion
                    
                    db.session.commit()
                    flash("Your profile has been successfully updated.", "success")
                    return redirect(url_for("employer_dashboard"))
                    
                except Exception as e:
                    db.session.rollback()
                    flash("Error updating employer profile", "danger")
                    print(f"Database error in update_employer_profile: {e}")

            industry_string = employer.industry or ""

            return render_template(
                "update_employer_profile.html", 
                form=form, 
                employer=employer, 
                industry_string=industry_string,
                profile_completion=profile_completion  # Add this
            )
            
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

    # =========================================================================

    # --- WTForms for Job Creation ---
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

    @app.route("/application/<int:app_id>/update_status", methods=["POST"])
    @login_required
    def update_application_status(app_id):
        if current_user.role != "employer":
            flash("Unauthorized", "danger")
            return redirect(url_for("index"))

        try:
            application = Application.query.get_or_404(app_id)
            new_status = request.form.get("status")
            
            if new_status:
                application.status = new_status
                db.session.commit()
                flash(f"Application status updated to {new_status}", "success")
            else:
                flash("No status provided", "warning")
                
        except Exception as e:
            db.session.rollback()
            flash("Error updating status", "danger")
            print(f"Error updating application status: {e}")
            
        return redirect(request.referrer)


    @app.route("/application/<int:app_id>/send_email", methods=["POST"])
    @login_required
    def send_email_to_applicant(app_id):
        if current_user.role != "employer":
            flash("Unauthorized", "danger")
            return redirect(url_for("index"))

        try:
            application = Application.query.get_or_404(app_id)
            employer = Employer.query.filter_by(user_id=current_user.id).first()
            
            subject = request.form.get("subject")
            body = request.form.get("body")
            
            if not subject or not body:
                flash("Subject and body are required", "danger")
                return redirect(request.referrer)

            # Send email
            msg = Message(
                subject=subject,
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[application.applicant.user.email],
            )
            msg.body = body
            mail.send(msg)
            
            flash("Email sent successfully!", "success")
            
        except Exception as e:
            flash(f"Error sending email: {str(e)}", "danger")
            print(f"Email send error: {e}")
            
        return redirect(request.referrer)


    @app.route("/employer/applications")
    @login_required
    def employer_applications():
        if current_user.role != "employer":
            flash("Only employers can view applications.", "warning")
            return redirect(url_for("index"))

        try:
            employer_profile = Employer.query.filter_by(user_id=current_user.id).first()
            
            if not employer_profile:
                flash("Please complete your employer profile first.", "warning")
                return redirect(url_for("employer_dashboard"))
            
            # Get all jobs for this employer (for the filter dropdown)
            jobs = Job.query.filter_by(employer_id=employer_profile.id).all()
            job_ids = [job.id for job in jobs]
            
            if not job_ids:
                return render_template("employer_applications.html", 
                                    applications=[], 
                                    jobs=[],
                                    employer_profile=employer_profile)
            
            # Get applications with all related data
            applications = (
                Application.query
                .filter(Application.job_id.in_(job_ids))
                .join(Job)
                .join(Applicant)
                .join(User, Applicant.user_id == User.id)
                .join(Profile, User.id == Profile.user_id)
                .order_by(Application.created_at.desc())
                .all()
            )
            
            applications_data = [(app, app.job, app.applicant.user.profile) for app in applications]
            
            return render_template("employer_applications.html", 
                                applications=applications_data, 
                                jobs=jobs,
                                employer_profile=employer_profile)
            
        except Exception as e:
            flash("Error loading applications", "danger")
            print(f"Database error in employer_applications: {e}")
            import traceback
            traceback.print_exc()
            return redirect(url_for("employer_dashboard"))

    @app.route("/delete_job/<int:job_id>", methods=["POST"])
    @login_required
    def delete_job(job_id):
        if current_user.role != "employer":
            flash("Unauthorized access.", "danger")
            return redirect(url_for("index"))

        try:
            # First, get the employer profile for the current user
            employer = Employer.query.filter_by(user_id=current_user.id).first()
            
            if not employer:
                flash("Employer profile not found.", "danger")
                return redirect(url_for("employer_dashboard"))
            
            # Now find the job that belongs to this employer
            job = Job.query.filter_by(id=job_id, employer_id=employer.id).first()
            
            if not job:
                flash("Job not found or you don't have permission to delete it.", "danger")
                return redirect(url_for("employer_dashboard"))

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
            import traceback
            traceback.print_exc()
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

    class RegistrationForm(FlaskForm):
        email = EmailField("Email", validators=[DataRequired()])
        password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
        role = SelectField("Role", choices=[("seeker", "Job Seeker"), ("employer", "Employer")], validators=[DataRequired()])
        full_name = StringField("Full Name")
        company_name = StringField("Company Name")
        submit = SubmitField("Register")


    @app.route("/register", methods=["GET", "POST"])
    def register():
        """Multi-step registration process - Entry point only"""
        # Clear any existing registration session if coming fresh
        if request.method == "GET" and not request.args.get('continue'):
            session.pop('registration_data', None)
            session.pop('registration_step', None)
            session.pop('registration_role', None)
        
        # Define steps for progress indicator
        steps = [
            {"number": 1, "label": "Account"},
            {"number": 2, "label": "Basic Info"},
            {"number": 3, "label": "Skills"},
            {"number": 4, "label": "Complete"}
        ]
        
        # Get current step from session or default to 1
        current_step = session.get('registration_step', 1)
        role = session.get('registration_role', None)
        
        # If user is already in the middle of registration, redirect to appropriate step
        if current_step > 1 and role:
            if role == 'seeker':
                if current_step == 2:
                    return redirect(url_for('register_step2_seeker'))
                elif current_step == 3:
                    return redirect(url_for('register_step3_seeker'))
                elif current_step == 4:
                    return redirect(url_for('register_step4_seeker'))
            else:  # employer
                if current_step == 2:
                    return redirect(url_for('register_step2_employer'))
                elif current_step == 3:
                    return redirect(url_for('register_step3_employer'))
                elif current_step == 4:
                    return redirect(url_for('register_step4_employer'))
        
        # Step 1: Account Information (only if starting fresh)
        form = Step1RegistrationForm()
        if form.validate_on_submit():
            # Check if email already exists
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user:
                flash("Email already registered. Please login or use a different email.", "danger")
                return render_template('registration/step1_account.html', 
                                    form=form, 
                                    steps=steps, 
                                    current_step=1)
            
            # Save step 1 data to session
            session['registration_data'] = {
                'email': form.email.data,
                'password': generate_password_hash(form.password.data),
                'role': form.role.data,
                'terms_accepted': True
            }
            session['registration_role'] = form.role.data
            session['registration_step'] = 2
            
            # Redirect to appropriate step 2 based on role
            if form.role.data == 'seeker':
                return redirect(url_for('register_step2_seeker'))
            else:
                return redirect(url_for('register_step2_employer'))
        
        return render_template('registration/step1_account.html', 
                            form=form, 
                            steps=steps, 
                            current_step=1)

    @app.route("/register/step2/seeker", methods=["GET", "POST"])
    def register_step2_seeker():
        """Step 2: Job Seeker Basic Information"""
        if 'registration_data' not in session or session.get('registration_role') != 'seeker':
            return redirect(url_for('register'))
        
        steps = [
            {"number": 1, "label": "Account"},
            {"number": 2, "label": "Basic Info"},
            {"number": 3, "label": "Skills"},
            {"number": 4, "label": "Complete"}
        ]
        
        form = Step2SeekerBasicForm()
        if form.validate_on_submit():
            # Update session data
            session['registration_data'].update({
                'full_name': form.full_name.data,
                'phone': form.phone.data,
                'city': form.city.data,
                'country': form.country.data,
                'current_job_title': form.current_job_title.data,
                'current_company': form.current_company.data,
                'years_experience': float(form.years_experience.data or 0),
                'education_level': form.education_level.data
            })
            session['registration_step'] = 3
            return redirect(url_for('register_step3_seeker'))
        
        # Pre-fill form if data exists
        if 'full_name' in session.get('registration_data', {}):
            form.full_name.data = session['registration_data'].get('full_name')
        if 'phone' in session.get('registration_data', {}):
            form.phone.data = session['registration_data'].get('phone')
        if 'city' in session.get('registration_data', {}):
            form.city.data = session['registration_data'].get('city')
        if 'country' in session.get('registration_data', {}):
            form.country.data = session['registration_data'].get('country')
        if 'current_job_title' in session.get('registration_data', {}):
            form.current_job_title.data = session['registration_data'].get('current_job_title')
        if 'current_company' in session.get('registration_data', {}):
            form.current_company.data = session['registration_data'].get('current_company')
        if 'years_experience' in session.get('registration_data', {}):
            form.years_experience.data = session['registration_data'].get('years_experience')
        if 'education_level' in session.get('registration_data', {}):
            form.education_level.data = session['registration_data'].get('education_level')
        
        return render_template('registration/step2_seeker_basic.html',
                            form=form,
                            steps=steps,
                            current_step=2)

    @app.route("/register/step3/seeker", methods=["GET", "POST"])
    def register_step3_seeker():
        """Step 3: Job Seeker Skills & Preferences"""
        if 'registration_data' not in session or session.get('registration_role') != 'seeker':
            return redirect(url_for('register'))
        
        steps = [
            {"number": 1, "label": "Account"},
            {"number": 2, "label": "Basic Info"},
            {"number": 3, "label": "Skills"},
            {"number": 4, "label": "Complete"}
        ]
        
        form = Step3SeekerSkillsForm()
        if form.validate_on_submit():
            # Update session data
            session['registration_data'].update({
                'skills': form.skills.data,
                'field_of_study': form.field_of_study.data,
                'university': form.university.data,
                'graduation_year': form.graduation_year.data,
                'preferred_job_types': form.preferred_job_types.data,
                'expected_salary': form.expected_salary.data,
                'remote_preference': form.remote_preference.data
            })
            session['registration_step'] = 4
            return redirect(url_for('register_step4_seeker'))
        
        # Pre-fill form if data exists
        if 'skills' in session.get('registration_data', {}):
            form.skills.data = session['registration_data'].get('skills')
        if 'field_of_study' in session.get('registration_data', {}):
            form.field_of_study.data = session['registration_data'].get('field_of_study')
        if 'university' in session.get('registration_data', {}):
            form.university.data = session['registration_data'].get('university')
        if 'graduation_year' in session.get('registration_data', {}):
            form.graduation_year.data = session['registration_data'].get('graduation_year')
        if 'expected_salary' in session.get('registration_data', {}):
            form.expected_salary.data = session['registration_data'].get('expected_salary')
        
        return render_template('registration/step3_seeker_skills.html',
                            form=form,
                            steps=steps,
                            current_step=3)

    @app.route("/register/step4/seeker", methods=["GET", "POST"])
    def register_step4_seeker():
        """Step 4: Job Seeker Bio & Summary"""
        if 'registration_data' not in session or session.get('registration_role') != 'seeker':
            return redirect(url_for('register'))
        
        steps = [
            {"number": 1, "label": "Account"},
            {"number": 2, "label": "Basic Info"},
            {"number": 3, "label": "Skills"},
            {"number": 4, "label": "Complete"}
        ]
        
        form = Step4SeekerBioForm()
        
        # Handle form submission
        if form.validate_on_submit():
            # Update session data
            updated_data = {
                'bio': form.bio.data,
                'linkedin_url': form.linkedin_url.data,
                'github_url': form.github_url.data,
                'portfolio_url': form.portfolio_url.data
            }
            session['registration_data'].update(updated_data)
            
            # Calculate completion percentage
            completion = calculate_seeker_completion(session['registration_data'])
            
            # Create user and profiles
            try:
                # Create User
                user = User(
                    email=session['registration_data']['email'],
                    password=session['registration_data']['password'],
                    role='seeker',
                    is_verified=False,
                    profile_completion=completion
                )
                db.session.add(user)
                db.session.flush()  # Get user ID without committing
                
                # Create Applicant
                applicant = Applicant(
                    user_id=user.id,
                    full_name=session['registration_data'].get('full_name'),
                    field_of_study=session['registration_data'].get('field_of_study'),
                    skills=session['registration_data'].get('skills'),
                    years_experience=session['registration_data'].get('years_experience', 0.0),
                    resume_text=session['registration_data'].get('bio', '')
                )
                db.session.add(applicant)
                
                # Create Profile
                profile = Profile(
                    user_id=user.id,
                    full_name=session['registration_data'].get('full_name', ''),
                    phone=session['registration_data'].get('phone'),
                    city=session['registration_data'].get('city'),
                    country=session['registration_data'].get('country'),
                    current_job_title=session['registration_data'].get('current_job_title'),
                    current_company=session['registration_data'].get('current_company'),
                    years_experience=session['registration_data'].get('years_experience', 0.0),
                    skills=session['registration_data'].get('skills'),
                    education_level=session['registration_data'].get('education_level'),
                    field_of_study=session['registration_data'].get('field_of_study'),
                    university=session['registration_data'].get('university'),
                    graduation_year=session['registration_data'].get('graduation_year'),
                    bio=session['registration_data'].get('bio'),
                    expected_salary=session['registration_data'].get('expected_salary'),
                    preferred_job_types=session['registration_data'].get('preferred_job_types'),
                    remote_preference=session['registration_data'].get('remote_preference'),
                    linkedin_url=session['registration_data'].get('linkedin_url'),
                    github_url=session['registration_data'].get('github_url'),
                    portfolio_url=session['registration_data'].get('portfolio_url')
                )
                db.session.add(profile)
                
                db.session.commit()
                
                # Send verification email
                token = generate_token(user.email)
                # verify_url = url_for("verify_email", token=token, _external=True)
                verify_url = f"http://102.209.87.208:8080{url_for('verify_email', token=token)}"
                msg = Message(
                    subject="Verify Your LastBit Account",
                    sender=app.config["MAIL_DEFAULT_SENDER"],
                    recipients=[user.email],
                )
                msg.body = f"""Welcome to LastBit!

    Thank you for registering as a Job Seeker.

    Please verify your email by clicking this link:
    {verify_url}

    This link expires in 1 hour.

    You can now:
    - Upload your resume
    - Browse job opportunities
    - Get personalized job recommendations

    Best regards,
    The LastBit Team"""
                mail.send(msg)
                
                # Store user data for complete page
                session['registration_complete_data'] = {
                    'full_name': session['registration_data'].get('full_name'),
                    'email': session['registration_data']['email'],
                    'role': 'seeker'
                }
                
                # Clear registration session
                session.pop('registration_data', None)
                session.pop('registration_step', None)
                session.pop('registration_role', None)
                
                return redirect(url_for('register_complete'))
                
            except Exception as e:
                db.session.rollback()
                flash(f"Error during registration: {str(e)}", "danger")
                return redirect(url_for('register'))
        
        # Pre-fill form if data exists
        if 'bio' in session.get('registration_data', {}):
            form.bio.data = session['registration_data'].get('bio')
        if 'linkedin_url' in session.get('registration_data', {}):
            form.linkedin_url.data = session['registration_data'].get('linkedin_url')
        if 'github_url' in session.get('registration_data', {}):
            form.github_url.data = session['registration_data'].get('github_url')
        if 'portfolio_url' in session.get('registration_data', {}):
            form.portfolio_url.data = session['registration_data'].get('portfolio_url')
        
        # Calculate completion percentage for display
        completion_data = session['registration_data'].copy()
        completion_data.update({
            'bio': form.bio.data or '',
            'linkedin_url': form.linkedin_url.data or '',
            'github_url': form.github_url.data or '',
            'portfolio_url': form.portfolio_url.data or ''
        })
        completion_percentage = calculate_seeker_completion(completion_data)
        
        return render_template('registration/step4_seeker_bio.html',
                            form=form,
                            steps=steps,
                            current_step=4,
                            completion_percentage=completion_percentage)

    # ================================================================================================================
    # EMPLOYER REGISTRATION ROUTES
    # ================================================================================================================

    @app.route("/register/step2/employer", methods=["GET", "POST"])
    def register_step2_employer():
        """Step 2: Employer Basic Information"""
        if 'registration_data' not in session or session.get('registration_role') != 'employer':
            return redirect(url_for('register'))
        
        steps = [
            {"number": 1, "label": "Account"},
            {"number": 2, "label": "Company Info"},
            {"number": 3, "label": "Location"},
            {"number": 4, "label": "Complete"}
        ]
        
        form = Step2EmployerBasicForm()
        if form.validate_on_submit():
            # Update session data
            session['registration_data'].update({
                'company_name': form.company_name.data,
                'company_email': form.company_email.data,
                'company_phone': form.company_phone.data,
                'website': form.website.data,
                'company_size': form.company_size.data,
                'founded_year': form.founded_year.data,
                'company_type': form.company_type.data
            })
            session['registration_step'] = 3
            return redirect(url_for('register_step3_employer'))
        
        # Pre-fill form if data exists
        if 'company_name' in session.get('registration_data', {}):
            form.company_name.data = session['registration_data'].get('company_name')
        
        return render_template('registration/step2_employer_basic.html',
                            form=form,
                            steps=steps,
                            current_step=2)

    @app.route("/register/step3/employer", methods=["GET", "POST"])
    def register_step3_employer():
        """Step 3: Employer Location Details"""
        if 'registration_data' not in session or session.get('registration_role') != 'employer':
            return redirect(url_for('register'))
        
        steps = [
            {"number": 1, "label": "Account"},
            {"number": 2, "label": "Company Info"},
            {"number": 3, "label": "Location"},
            {"number": 4, "label": "Complete"}
        ]
        
        form = Step3EmployerLocationForm()
        if form.validate_on_submit():
            # Update session data
            session['registration_data'].update({
                'address': form.address.data,
                'city': form.city.data,
                'state': form.state.data,
                'country': form.country.data,
                'zip_code': form.zip_code.data
            })
            session['registration_step'] = 4
            return redirect(url_for('register_step4_employer'))
        
        # Pre-fill form if data exists
        if 'city' in session.get('registration_data', {}):
            form.city.data = session['registration_data'].get('city')
        if 'country' in session.get('registration_data', {}):
            form.country.data = session['registration_data'].get('country')
        
        return render_template('registration/step3_employer_location.html',
                            form=form,
                            steps=steps,
                            current_step=3)

    @app.route("/register/step4/employer", methods=["GET", "POST"])
    def register_step4_employer():
        """Step 4: Employer Industry & Description"""
        if 'registration_data' not in session or session.get('registration_role') != 'employer':
            return redirect(url_for('register'))
        
        steps = [
            {"number": 1, "label": "Account"},
            {"number": 2, "label": "Company Info"},
            {"number": 3, "label": "Location"},
            {"number": 4, "label": "Complete"}
        ]
        
        form = Step4EmployerIndustryForm()
        
        # Handle form submission
        if form.validate_on_submit():
            # Update session data
            updated_data = {
                'industry': form.industry.data,
                'sector': form.sector.data,
                'description': form.description.data,
                'linkedin_url': form.linkedin_url.data,
                'x_url': form.x_url.data
            }
            session['registration_data'].update(updated_data)
            
            # Calculate completion percentage
            completion = calculate_employer_completion(session['registration_data'])
            
            # Create user and profiles
            try:
                # Create User
                user = User(
                    email=session['registration_data']['email'],
                    password=session['registration_data']['password'],
                    role='employer',
                    is_verified=False,
                    profile_completion=completion
                )
                db.session.add(user)
                db.session.flush()  # Get user ID without committing
                
                # Create Employer
                employer = Employer(
                    user_id=user.id,
                    company_name=session['registration_data'].get('company_name'),
                    company_email=session['registration_data'].get('company_email'),
                    company_phone=session['registration_data'].get('company_phone'),
                    website=session['registration_data'].get('website'),
                    company_size=session['registration_data'].get('company_size'),
                    founded_year=session['registration_data'].get('founded_year'),
                    company_type=session['registration_data'].get('company_type'),
                    address=session['registration_data'].get('address'),
                    city=session['registration_data'].get('city'),
                    state=session['registration_data'].get('state'),
                    country=session['registration_data'].get('country'),
                    zip_code=session['registration_data'].get('zip_code'),
                    industry=session['registration_data'].get('industry'),
                    sector=session['registration_data'].get('sector'),
                    description=session['registration_data'].get('description'),
                    linkedin_url=session['registration_data'].get('linkedin_url'),
                    x_url=session['registration_data'].get('x_url')
                )
                db.session.add(employer)
                
                db.session.commit()
                
                # Send verification email
                token = generate_token(user.email)
                # verify_url = url_for("verify_email", token=token, _external=True)
                verify_url = f"http://102.209.87.208:8080{url_for('verify_email', token=token)}"
                msg = Message(
                    subject="Verify Your LastBit Employer Account",
                    sender=app.config["MAIL_DEFAULT_SENDER"],
                    recipients=[user.email],
                )
                msg.body = f"""Welcome to LastBit!

    Thank you for registering as an Employer.

    Please verify your email by clicking this link:
    {verify_url}

    This link expires in 1 hour.

    You can now:
    - Post job openings
    - Browse candidate profiles
    - Manage applications

    Best regards,
    The LastBit Team"""
                mail.send(msg)
                
                # Store user data for complete page
                session['registration_complete_data'] = {
                    'company_name': session['registration_data'].get('company_name'),
                    'email': session['registration_data']['email'],
                    'role': 'employer'
                }
                
                # Clear registration session
                session.pop('registration_data', None)
                session.pop('registration_step', None)
                session.pop('registration_role', None)
                
                return redirect(url_for('register_complete'))
                
            except Exception as e:
                db.session.rollback()
                flash(f"Error during registration: {str(e)}", "danger")
                return redirect(url_for('register'))
        
        # Pre-fill form if data exists
        if 'industry' in session.get('registration_data', {}):
            form.industry.data = session['registration_data'].get('industry')
        if 'sector' in session.get('registration_data', {}):
            form.sector.data = session['registration_data'].get('sector')
        if 'description' in session.get('registration_data', {}):
            form.description.data = session['registration_data'].get('description')
        
        # Calculate completion percentage for display
        completion_data = session['registration_data'].copy()
        completion_data.update({
            'industry': form.industry.data or '',
            'sector': form.sector.data or '',
            'description': form.description.data or '',
            'linkedin_url': form.linkedin_url.data or '',
            'x_url': form.x_url.data or ''
        })
        completion_percentage = calculate_employer_completion(completion_data)
        
        return render_template('registration/step4_employer_industry.html',
                            form=form,
                            steps=steps,
                            current_step=4,
                            completion_percentage=completion_percentage)

    # ================================================================================================================

    def calculate_seeker_completion(data):
        """Calculate profile completion percentage for job seeker"""
        required_fields = ['full_name', 'email']
        important_fields = ['skills', 'years_experience', 'education_level', 'bio']
        optional_fields = ['phone', 'city', 'country', 'current_job_title', 'current_company',
                        'field_of_study', 'university', 'graduation_year', 'expected_salary',
                        'preferred_job_types', 'remote_preference', 'linkedin_url',
                        'github_url', 'portfolio_url']
        
        total_weight = 0
        completed_weight = 0
        
        # Required fields weight: 40%
        for field in required_fields:
            total_weight += 20  # 20% each
            if data.get(field):
                completed_weight += 20
        
        # Important fields weight: 40%
        for field in important_fields:
            total_weight += 10  # 10% each
            if data.get(field):
                completed_weight += 10
        
        # Optional fields weight: 20%
        for field in optional_fields:
            total_weight += 1.43  # 20% / 14 fields ≈ 1.43% each
            if data.get(field):
                completed_weight += 1.43
        
        if total_weight == 0:
            return 0
        
        return min(100, int((completed_weight / total_weight) * 100))

    def calculate_employer_completion(data):
        """Calculate profile completion percentage for employer"""
        required_fields = ['company_name', 'company_email']
        important_fields = ['industry', 'description', 'address', 'company_size']
        optional_fields = ['company_phone', 'website', 'founded_year', 'company_type',
                        'city', 'state', 'country', 'zip_code', 'sector',
                        'linkedin_url', 'x_url']
        
        total_weight = 0
        completed_weight = 0
        
        # Required fields weight: 40%
        for field in required_fields:
            total_weight += 20  # 20% each
            if data.get(field):
                completed_weight += 20
        
        # Important fields weight: 40%
        for field in important_fields:
            total_weight += 10  # 10% each
            if data.get(field):
                completed_weight += 10
        
        # Optional fields weight: 20%
        for field in optional_fields:
            total_weight += 1.82  # 20% / 11 fields ≈ 1.82% each
            if data.get(field):
                completed_weight += 1.82
        
        if total_weight == 0:
            return 0
        
        return min(100, int((completed_weight / total_weight) * 100))

    @app.route("/register/complete")
    def register_complete():
        """Registration completion page"""
        if 'registration_complete_data' not in session:
            return redirect(url_for('register'))
        
        complete_data = session['registration_complete_data']
        
        return render_template('registration/complete.html', complete_data=complete_data)

    @app.route("/clear_registration_session", methods=["POST"])
    def clear_registration_session():
        """Clear registration session data"""
        session.pop('registration_data', None)
        session.pop('registration_step', None)
        session.pop('registration_role', None)
        session.pop('registration_complete_data', None)
        return jsonify({"success": True})

    # ================================================================================================================================

    
    @app.route("/resend_verification", methods=["GET", "POST"])
    def resend_verification():
        if request.method == "POST":
            email = request.form.get("email")
            user = User.query.filter_by(email=email).first()
            
            if not user:
                flash("Email not found. Please register.", "danger")
                return redirect(url_for("register"))
            
            if user.is_verified:
                flash("Email already verified. Please log in.", "info")
                return redirect(url_for("login"))
            
            # DON'T delete expired users - just resend verification
            # Check if expired to show appropriate message
            if user.is_verification_expired(expiry_minutes=1):
                flash_message = "Your verification has expired. A new verification email has been sent."
            else:
                time_left = user.get_verification_time_left(expiry_minutes=60)
                minutes_left = int(time_left // 60)
                seconds_left = int(time_left % 60)
                flash_message = f"A new verification email has been sent. Time left on previous link: {minutes_left}m {seconds_left}s"
            
            # Always resend verification email (even if expired)
            try:
                token = generate_token(user.email)
                # verify_url = url_for("verify_email", token=token, _external=True)
                verify_url = f"http://102.209.87.208:8080{url_for('verify_email', token=token)}"
                
                msg = Message(
                    subject="LastBit - New Verification Email",
                    sender=app.config["MAIL_DEFAULT_SENDER"],
                    recipients=[user.email],
                )
                msg.body = f"""Hello,
                
    You requested a new verification email for LastBit.

    Please verify your email by clicking this link:
    {verify_url}

    This link expires in 1 hour.

    If you didn't request this, please ignore this email.

    Best regards,
    The LastBit Team"""
                
                mail.send(msg)
                flash(f"{flash_message} Please check your inbox.", "success")
                return redirect(url_for("login"))
                
            except Exception as e:
                flash(f"Error sending verification email: {str(e)}", "danger")
                print(f"Resend verification error: {e}")
        
        return render_template("resend_verification.html")


    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data

            try:
                user = User.query.filter_by(email=email).first()
                
                if user:
                    # Check if user is unverified
                    if not user.is_verified:
                        # Check if expired to show appropriate message
                        if user.is_verification_expired(expiry_minutes=60):
                            flash(
                                Markup(
                                    "Your verification link has expired. "
                                    f'<a href="{url_for("resend_verification")}" class="alert-link">Click here to request a new verification email</a>'
                                ),
                                "warning"
                            )
                        else:
                            time_left = user.get_verification_time_left(expiry_minutes=60)
                            minutes_left = int(time_left // 60)
                            seconds_left = int(time_left % 60)
                            flash(
                                Markup(
                                    f"Please verify your email before logging in. "
                                    f"Time left: {minutes_left}m {seconds_left}s. "
                                    f'<a href="{url_for("resend_verification")}" class="alert-link">Resend verification email</a>'
                                ),
                                "warning"
                            )
                        return redirect(url_for("login"))
                
                # Rest of your login logic...
                
                # If user exists and password is correct (and verified)
                if user and check_password_hash(user.password, password):
                    if not user.is_verified:
                        # This shouldn't happen due to checks above, but just in case
                        flash("Please verify your email before logging in.", "warning")
                        return redirect(url_for("login"))
                        
                    login_user(user, remember=form.remember.data)
                    
                    # Update last login and count
                    user.last_login = datetime.utcnow()
                    user.login_count = (user.login_count or 0) + 1
                    db.session.commit()
                    
                    flash("Logged in successfully!", "success")
                    
                    if user.role == "seeker":
                        return redirect(url_for("seeker_dashboard"))
                    elif user.role == "employer":
                        return redirect(url_for("employer_dashboard"))
                else:
                    flash("Invalid credentials", "danger")
                    return redirect(url_for("login"))
                    
            except Exception as e:
                flash("Error during login", "danger")
                print(f"Database error in login: {e}")
                return redirect(url_for("login"))
        
        return render_template("login.html", form=form)

# =====================================================================================================================  
    
    @app.route("/verify/<token>")
    def verify_email(token):
        # First verify the token
        email = confirm_token(token)
        if not email:
            flash("The verification link is invalid or has expired.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Account not found.", "danger")
            return redirect(url_for("login"))

        # Check if user is already verified
        if user.is_verified:
            flash("Account already verified. Please log in.", "info")
            return redirect(url_for("login"))
        
        # Check if verification has expired (1 minute for testing)
        # Even if expired, we still allow verification
        # if user.is_verification_expired(expiry_minutes=1):
        #     flash(
        #         "Your verification link has expired, but we've verified your email anyway. "
        #         "You can now log in.",
        #         "warning"
        #     )
        
        # Verify the user (whether expired or not)
        user.is_verified = True
        db.session.commit()
        flash("Your email has been verified! You can now log in.", "success")
        return redirect(url_for("login"))

    @app.route('/static/<path:filename>')
    def serve_static(filename):
        return send_from_directory('static', filename)

    # Also add a route for style.css if you have one
    @app.route('/style.css')
    def style_css():
        return send_from_directory('static', 'style.css')
   

# ======================================================================= TESTING CODE START ===============================================================================================

    @app.route("/test/health")
    def health_check():
        """Check if the application is live"""
        zimbabwe_time = get_zimbabwe_time()
        return jsonify({
            "status": "Live",
            # "timestamp": zimbabwe_time.isoformat(),
            "timestamp": zimbabwe_time.strftime("%Y-%m-%d %H:%M:%S"),
            "service": "LastBit Job Portal"
        })
    
    @app.route("/test/db")
    def test_db():
        """Test database connection"""
        zimbabwe_time = get_zimbabwe_time()
        try:
            # Test query from each table
            users_count = User.query.count()
            seekers_count = User.query.filter_by(role='seeker').count()
            employers_count = User.query.filter_by(role='employer').count()
            profiles_count = Profile.query.count()
            jobs_count = Job.query.count()
            applications_count = Application.query.count()
            return jsonify({
                "status": "Database connection successful",
                "database_stats": {
                    "total_users" : users_count,
                    "seekers": seekers_count,
                    "employers": employers_count,
                    "profiles": profiles_count,
                    "jobs": jobs_count,
                    "applications": applications_count
                },
                "timestamp": zimbabwe_time.strftime("%Y-%m-%d %H:%M:%S")
            })
        except Exception as e:
            return jsonify({
                "status": "Database connection failed",
                "error": str(e),
                "timestamp": zimbabwe_time.strftime("%Y-%m-%d %H:%M:%S")
            }), 500
        
    @app.route("/test/users/details")
    @login_required
    def test_users_details():
        """Get detailed user statistics (requires login)"""
        zimbabwe_time = get_zimbabwe_time()
        try:
            # Get all users with their details
            users = User.query.all()

            user_details = []
            for user in users:
                user_data = {
                    "id": user.id,
                    "email": user.email,
                    "role": user.role,
                    "is_verified": user.is_verified,
                    "profile_completion": user.profile_completion,
                    "created_at": user.created_at.isoformat() if user.created_at else None,
                    "last_login": user.last_login.isoformat() if user.last_login else None
                }
                
                # Add role-specific details
                if user.role == "seeker":
                    profile = Profile.query.filter_by(user_id=user.id).first()
                    applicant = Applicant.query.filter_by(user_id=user.id).first()
                    user_data.update({
                        "profile_exists": profile is not None,
                        "applicant_exists": applicant is not None,
                        "has_resume": profile.resume if profile and profile.resume else False
                    })
                elif user.role == "employer":
                    employer = Employer.query.filter_by(user_id=user.id).first()
                    user_data.update({
                        "employer_exists": employer is not None,
                        "company_name": employer.company_name if employer else None,
                        "jobs_posted": Job.query.filter_by(employer_id=employer.id).count() if employer else 0
                    })
                
                user_details.append(user_data)
            
            return jsonify({
                "total_users": len(user_details),
                "users": user_details
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "error": str(e),
            }), 500

    @app.route("/test/employers/summary")
    def test_employers_summary():
        """Get summary of all employers"""
        try:
            employers = Employer.query.all()
            employer_list = []
            for emp in employers:
                user = User.query.get(emp.user_id)
                jobs_count = Job.query.filter_by(employer_id=emp.id).count()
                
                employer_list.append({
                    "id": emp.id,
                    "company_name": emp.company_name,
                    "company_email": emp.company_email,
                    "industry": emp.industry,
                    "location": f"{emp.city}, {emp.country}" if emp.city and emp.country else "Not specified",
                    "user_email": user.email if user else "Unknown",
                    "user_verified": user.is_verified if user else False,
                    "jobs_posted": jobs_count,
                    "company_size": emp.company_size,
                    "website": emp.website
                })
            
            return jsonify({
                "total_employers": len(employer_list),
                "employers": employer_list
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "error": str(e)
            }), 500

    @app.route("/test/seekers/summary")
    def test_seekers_summary():
        """Get summary of all job seekers"""
        try:
            seekers = User.query.filter_by(role="seeker").all()
            seeker_list = []
            for user in seekers:
                profile = Profile.query.filter_by(user_id=user.id).first()
                applicant = Applicant.query.filter_by(user_id=user.id).first()
                
                seeker_data = {
                    "id": user.id,
                    "email": user.email,
                    "is_verified": user.is_verified,
                    "profile_completion": user.profile_completion,
                    "has_profile": profile is not None,
                    "has_applicant": applicant is not None
                }
                
                if profile:
                    seeker_data.update({
                        "full_name": profile.full_name,
                        "skills": profile.skills,
                        "experience_years": profile.years_experience,
                        "has_resume": bool(profile.resume),
                        "location": f"{profile.city}, {profile.country}" if profile.city and profile.country else "Not specified",
                        "job_title": profile.current_job_title
                    })
                
                seeker_list.append(seeker_data)
            
            return jsonify({
                "total_seekers": len(seeker_list),
                "seekers": seeker_list
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "error": str(e)
            }), 500

    @app.route("/test/jobs/stats")
    def test_jobs_stats():
        """Get statistics about job postings"""
        try:
            total_jobs = Job.query.count()
            active_jobs = Job.query.filter_by(status="active").count()
            featured_jobs = Job.query.filter_by(is_featured=True).count()
            # Get jobs by type
            job_types = {}
            jobs_by_type = db.session.query(Job.job_type, db.func.count(Job.id)).group_by(Job.job_type).all()
            for job_type, count in jobs_by_type:
                job_types[job_type or "Not specified"] = count
            
            # Get jobs with most applications
            jobs_with_apps = db.session.query(
                Job.title, 
                Job.id,
                db.func.count(Application.id).label('app_count')
            ).outerjoin(Application, Job.id == Application.job_id
            ).group_by(Job.id, Job.title
            ).order_by(db.func.count(Application.id).desc()
            ).limit(10).all()
            
            top_jobs = [{"title": title, "id": id, "applications": app_count} 
                    for title, id, app_count in jobs_with_apps]
            
            return jsonify({
                "total_jobs": total_jobs,
                "active_jobs": active_jobs,
                "featured_jobs": featured_jobs,
                "job_types_distribution": job_types,
                "top_jobs_by_applications": top_jobs
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "error": str(e)
            }), 500

    @app.route("/test/system/status")
    def test_system_status():
        """Comprehensive system status check"""
        try:
            # Check database connectivity
            db.session.execute("SELECT 1")
            db_status = "connected"
            # Check upload folder
            upload_folder = app.config.get("UPLOAD_FOLDER", "")
            upload_folder_exists = os.path.exists(upload_folder) if upload_folder else False
            
            # Check email configuration
            mail_config = {
                "server": app.config.get("MAIL_SERVER"),
                "port": app.config.get("MAIL_PORT"),
                "use_tls": app.config.get("MAIL_USE_TLS"),
                "username_set": bool(app.config.get("MAIL_USERNAME")),
                "password_set": bool(app.config.get("MAIL_PASSWORD"))
            }
            
            # Get counts
            users_count = User.query.count()
            jobs_count = Job.query.count()
            applications_count = Application.query.count()
            
            return jsonify({
                "system": {
                    "environment": "production" if app.config.get("IS_PRODUCTION") else "development",
                    "debug_mode": app.config.get("DEBUG", False),
                    "database": db_status,
                    "upload_folder": {
                        "path": upload_folder,
                        "exists": upload_folder_exists,
                        "writable": os.access(upload_folder, os.W_OK) if upload_folder_exists else False
                    },
                    "mail_config": mail_config
                },
                "counts": {
                    "users": users_count,
                    "seekers": User.query.filter_by(role="seeker").count(),
                    "employers": User.query.filter_by(role="employer").count(),
                    "jobs": jobs_count,
                    "applications": applications_count,
                    "profiles": Profile.query.count()
                },
                "timestamp": datetime.utcnow().isoformat(),
                "uptime": "N/A"  # You could add uptime tracking with a global variable
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }), 500

# ======================================================================= TESTING CODE END ===============================================================================================


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