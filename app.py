from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from sqlalchemy import func
import re
import os
from dotenv import load_dotenv

from models import Timetable, ExamResult, PaymentPlan, Club, ClubMembership, SportsMatch, SportsAchievement, CommunicationLog, ExchangeRate
from datetime import time

# Load environment variables
load_dotenv()

from config import Config
from models import db, bcrypt, User, Student, Teacher, Term, Fee, Payment, Subject, Grade, Attendance, StockItem, Sport, SportRegistration

from functools import wraps
from permissions import can_access_resource, filter_by_role, ENDPOINT_PERMISSIONS


app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
CORS(app, supports_credentials=True)
jwt = JWTManager(app)
# db.init_app(app)
db.init_app(app)
bcrypt.init_app(app)

# Zimbabwe validation functions
def validate_national_id(national_id):
    pattern = r'^\d{2}-\d{6,7}[A-Z]\d{2}$'
    return re.match(pattern, national_id) is not None

def validate_phone(phone):
    pattern = r'^(\+263|0)\d{9}$'
    return re.match(pattern, phone) is not None

def role_required(allowed_roles=None, resource_type=None, action='view'):
    """Enhanced role decorator with resource checking"""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user or not user.is_active:
                return jsonify({'error': 'User not found or inactive'}), 401
            
            # Check if role is allowed
            if allowed_roles and user.role not in allowed_roles:
                return jsonify({'error': f'Access denied. {user.role} cannot access this resource'}), 403
            
            # Check resource-specific permissions
            if resource_type:
                if not can_access_resource(user.role, resource_type, action):
                    return jsonify({'error': f'Access denied. {user.role} cannot {action} {resource_type}'}), 403
            
            # Store user info in request context
            request.current_user = user
            request.current_user_id = current_user_id
            request.user_role = user.role
            
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# Helper function to apply data filtering
def apply_data_filter(query, model, user_role, user_id):
    """Apply data filtering based on user role"""
    if user_role == 'teacher':
        teacher = Teacher.query.filter_by(user_id=user_id).first()
        if teacher and teacher.classes_assigned:
            classes = [c.strip() for c in teacher.classes_assigned.split(',')]
            if model == Student:
                return query.filter(Student.class_name.in_(classes))
            elif model == ExamResult:
                return query.join(Student).filter(Student.class_name.in_(classes))
            elif model == Attendance:
                return query.join(Student).filter(Student.class_name.in_(classes))
    
    elif user_role == 'parent':
        user = User.query.get(user_id)
        if user and user.email:
            if model == Student:
                return query.filter(Student.guardian_email == user.email)
            elif model == Payment:
                return query.join(Student).filter(Student.guardian_email == user.email)
            elif model == ExamResult:
                return query.join(Student).filter(Student.guardian_email == user.email)
    
    elif user_role == 'student':
        student = Student.query.filter_by(user_id=user_id).first()
        if student:
            if model == Student:
                return query.filter(Student.id == student.id)
            elif model == ExamResult:
                return query.filter(ExamResult.student_id == student.id)
            elif model == Attendance:
                return query.filter(Attendance.student_id == student.id)
            elif model == Payment:
                return query.filter(Payment.student_id == student.id)
    
    return query


def apply_data_filter(query, model, user_role, user_id):
    """Apply role-based filtering to queries"""
    if user_role == 'teacher':
        # Teachers can only see students in their classes
        teacher = Teacher.query.filter_by(user_id=user_id).first()
        if teacher and teacher.classes_assigned:
            classes = [c.strip() for c in teacher.classes_assigned.split(',')]
            if hasattr(model, 'class_name'):
                query = query.filter(model.class_name.in_(classes))
    
    elif user_role == 'parent':
        # Parents can only see their own children
        user = User.query.get(user_id)
        if user and user.email:
            query = query.filter(model.guardian_email == user.email)
    
    elif user_role == 'student':
        # Students can only see themselves
        student = Student.query.filter_by(user_id=user_id).first()
        if student:
            query = query.filter(model.id == student.id)
    
    return query


# Create tables
with app.app_context():
    db.create_all()
    
    # Create default developer account if not exists
    if not User.query.filter_by(role='developer').first():
        dev = User(
            username='developer',
            email='dev@school.com',
            role='developer',
            full_name='System Developer',
            phone='+263000000000'
        )
        dev.set_password('dev123456')
        db.session.add(dev)
        db.session.commit()
        print("Developer account created: username='developer', password='dev123456'")
    
    # Create default terms for 2026
    year = 2025
    if not Term.query.filter_by(year=year).first():
        terms = [
            Term(term_number=1, year=year, start_date=datetime(2026, 1, 10), end_date=datetime(2026, 4, 4), is_current=True),
            Term(term_number=2, year=year, start_date=datetime(2026, 5, 6), end_date=datetime(2026, 8, 8), is_current=False),
            Term(term_number=3, year=year, start_date=datetime(2026, 9, 2), end_date=datetime(2026, 12, 5), is_current=False),
        ]
        for term in terms:
            db.session.add(term)
        db.session.commit()
        print("Default terms created for 2025")
    
    # Create sample subjects if none exist
    if Subject.query.count() == 0:
        sample_subjects = [
            Subject(name='Mathematics', code='MATH'),
            Subject(name='English', code='ENG'),
            Subject(name='Science', code='SCI'),
            Subject(name='History', code='HIST'),
            Subject(name='Geography', code='GEOG'),
        ]
        for subject in sample_subjects:
            db.session.add(subject)
        db.session.commit()
        print("Sample subjects created")

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account is deactivated'}), 403
    
    # Create access token
    access_token = create_access_token(identity=str(user.id))
    
    return jsonify({
        'access_token': access_token,
        'user': user.to_dict()
    }), 200

@app.route('/api/v1/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(user.to_dict()), 200

# ==================== STUDENT MANAGEMENT ====================

# @app.route('/api/v1/students', methods=['GET'])
# @jwt_required()
# def get_students():
#     class_name = request.args.get('class')
#     stream = request.args.get('stream')
    
#     query = Student.query.filter_by(is_active=True)
    
#     if class_name:
#         query = query.filter_by(class_name=class_name)
#     if stream:
#         query = query.filter_by(stream=stream)
    
#     students = query.all()
#     return jsonify([s.to_dict() for s in students]), 200

@app.route('/api/v1/students', methods=['GET'])
@jwt_required()
@role_required(resource_type='students', action='view')
def get_students():
    user = request.current_user
    user_role = user.role
    user_id = user.id
    
    query = Student.query.filter_by(is_active=True)
    
    # Apply role-based filtering
    query = apply_data_filter(query, Student, user_role, user_id)
    
    # Additional filters
    class_name = request.args.get('class_name')
    if class_name and user_role in ['developer', 'principal', 'teacher']:
        query = query.filter_by(class_name=class_name)
    
    stream = request.args.get('stream')
    if stream and user_role in ['developer', 'principal', 'teacher']:
        query = query.filter_by(stream=stream)
    
    students = query.all()
    return jsonify([s.to_dict() for s in students]), 200

@app.route('/api/v1/students', methods=['POST'])
@role_required(['developer', 'principal', 'teacher'])
def create_student():
    data = request.get_json()
    
    # Validate required fields
    if not data.get('full_name'):
        return jsonify({'error': 'Full name is required'}), 400
    
    # Validate national ID if provided
    if data.get('national_id'):
        if not validate_national_id(data['national_id']):
            return jsonify({'error': 'Invalid national ID format. Expected format: 00-000000A00'}), 400
        
        # Check for duplicate national ID
        if Student.query.filter_by(national_id=data['national_id']).first():
            return jsonify({'error': 'Student with this national ID already exists'}), 400
    
    student = Student(
        national_id=data.get('national_id'),  # Use get() which returns None if not present
        full_name=data['full_name'],
        date_of_birth=datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date() if data.get('date_of_birth') else None,
        gender=data.get('gender'),
        address=data.get('address'),
        phone=data.get('phone'),
        guardian_name=data.get('guardian_name'),
        guardian_phone=data.get('guardian_phone'),
        guardian_email=data.get('guardian_email'),
        class_name=data.get('class_name'),
        stream=data.get('stream')
    )
    
    db.session.add(student)
    db.session.commit()
    
    return jsonify(student.to_dict()), 201

# @app.route('/api/v1/students/<int:student_id>', methods=['GET'])
# @jwt_required()
# def get_student(student_id):
#     student = Student.query.get_or_404(student_id)
#     return jsonify(student.to_dict()), 200

@app.route('/api/v1/students/<int:student_id>', methods=['GET'])
@jwt_required()
@role_required(resource_type='students', action='view')
def get_student(student_id):
    user = request.current_user
    user_role = user.role
    user_id = user.id
    
    student = Student.query.get_or_404(student_id)
    
    # Check if user has access to this specific student
    if user_role == 'teacher':
        teacher = Teacher.query.filter_by(user_id=user_id).first()
        if teacher and teacher.classes_assigned:
            classes = [c.strip() for c in teacher.classes_assigned.split(',')]
            if student.class_name not in classes:
                return jsonify({'error': 'You do not have access to this student'}), 403
    
    elif user_role == 'parent':
        user = User.query.get(user_id)
        if user and user.email:
            if student.guardian_email != user.email:
                return jsonify({'error': 'You do not have access to this student'}), 403
    
    elif user_role == 'student':
        student_account = Student.query.filter_by(user_id=user_id).first()
        if student_account and student_account.id != student_id:
            return jsonify({'error': 'You can only view your own profile'}), 403
    
    return jsonify(student.to_dict()), 200

@app.route('/api/v1/students/<int:student_id>', methods=['PUT'])
@role_required(['developer', 'principal', 'teacher'])
def update_student(student_id):
    student = Student.query.get_or_404(student_id)
    data = request.get_json()
    
    # Update fields
    for field in ['full_name', 'address', 'phone', 'guardian_name', 'guardian_phone', 'guardian_email', 'class_name', 'stream', 'gender']:
        if field in data:
            setattr(student, field, data[field])
    
    if 'date_of_birth' in data:
        student.date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date()
    
    db.session.commit()
    return jsonify(student.to_dict()), 200

@app.route('/api/v1/students/<int:student_id>', methods=['DELETE'])
@role_required(['developer', 'principal'])
def delete_student(student_id):
    student = Student.query.get_or_404(student_id)
    student.is_active = False
    db.session.commit()
    return jsonify({'message': 'Student deactivated successfully'}), 200

# ==================== TEACHER MANAGEMENT ====================

@app.route('/api/v1/teachers', methods=['GET'])
@jwt_required()
def get_teachers():
    teachers = Teacher.query.filter_by(is_active=True).all()
    return jsonify([t.to_dict() for t in teachers]), 200

@app.route('/api/v1/teachers', methods=['POST'])
@role_required(['developer', 'principal'])
def create_teacher():
    data = request.get_json()
    
    if not data.get('staff_id') or not data.get('full_name'):
        return jsonify({'error': 'Staff ID and full name are required'}), 400
    
    if Teacher.query.filter_by(staff_id=data['staff_id']).first():
        return jsonify({'error': 'Staff ID already exists'}), 400
    
    teacher = Teacher(
        staff_id=data['staff_id'],
        full_name=data['full_name'],
        national_id=data.get('national_id'),
        phone=data.get('phone'),
        email=data.get('email'),
        subjects=','.join(data['subjects']) if isinstance(data.get('subjects'), list) else data.get('subjects'),
        classes_assigned=','.join(data['classes_assigned']) if isinstance(data.get('classes_assigned'), list) else data.get('classes_assigned'),
        qualification=data.get('qualification')
    )
    
    db.session.add(teacher)
    db.session.commit()
    
    return jsonify(teacher.to_dict()), 201

# ==================== FEE MANAGEMENT ====================

@app.route('/api/v1/fees', methods=['GET'])
@jwt_required()
def get_fees():
    student_id = request.args.get('student_id')
    if student_id:
        fees = Fee.query.filter_by(student_id=student_id).all()
    else:
        fees = Fee.query.all()
    return jsonify([f.to_dict() for f in fees]), 200


@app.route('/api/v1/fees', methods=['POST'])
@role_required(['developer', 'principal'])
def create_fee():
    data = request.get_json()
    
    required = ['student_id', 'term_id', 'amount', 'currency']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400
    
    # Convert amount to float
    try:
        amount = float(data['amount'])
    except (TypeError, ValueError):
        return jsonify({'error': 'Amount must be a valid number'}), 400
    
    rate_of_day = float(data.get('rate_of_day', 1.0))
    currency = data['currency']
    
    amount_usd = None
    amount_zwg = None
    
    if currency == 'USD':
        amount_usd = amount
        amount_zwg = amount * rate_of_day if rate_of_day else None
    else:  # ZWG or other currency
        amount_zwg = amount
        amount_usd = amount / rate_of_day if rate_of_day else None
    
    # Parse due_date if provided
    due_date = None
    if data.get('due_date'):
        try:
            due_date = datetime.strptime(data['due_date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'due_date must be in YYYY-MM-DD format'}), 400
    
    fee = Fee(
        student_id=data['student_id'],
        term_id=data['term_id'],
        amount=amount,  # Store as float
        currency=currency,
        rate_of_day=rate_of_day,
        amount_usd=amount_usd,
        amount_zwg=amount_zwg,
        fee_type=data.get('fee_type'),
        due_date=due_date
    )
    
    db.session.add(fee)
    db.session.commit()
    
    return jsonify(fee.to_dict()), 201

@app.route('/api/v1/payments', methods=['GET'])
@jwt_required()
def get_payments():
    """Get all payments (with optional filters)"""
    student_id = request.args.get('student_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = Payment.query
    
    if student_id:
        query = query.filter_by(student_id=student_id)
    
    if start_date:
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(Payment.payment_date >= start)
        except ValueError:
            pass
    
    if end_date:
        try:
            end = datetime.strptime(end_date, '%Y-%m-%d')
            query = query.filter(Payment.payment_date <= end)
        except ValueError:
            pass
    
    # Order by most recent first
    payments = query.order_by(Payment.payment_date.desc()).all()
    
    return jsonify([payment.to_dict() for payment in payments]), 200

@app.route('/api/v1/payments', methods=['POST'])
@role_required(['developer', 'principal'])
def create_payment():
    data = request.get_json()
    
    required = ['student_id', 'amount', 'currency', 'payment_method']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400
    
    # Convert amount to float
    try:
        amount = float(data['amount'])
    except (TypeError, ValueError):
        return jsonify({'error': 'Amount must be a valid number'}), 400
    
    # Check if amount is within database limits (NUMERIC(10,2) max is 9,999,999.99)
    if amount > 9999999.99:
        return jsonify({'error': 'Amount exceeds maximum allowed value'}), 400
    
    # Convert student_id to integer
    try:
        student_id = int(data['student_id'])
    except (TypeError, ValueError):
        return jsonify({'error': 'student_id must be a valid integer'}), 400
    
    # Generate receipt number
    receipt_number = f"RCP-{datetime.now().strftime('%Y%m%d%H%M%S')}-{student_id}"
    
    # Convert rate_of_day to float
    try:
        rate_of_day = float(data.get('rate_of_day', 1.0))
    except (TypeError, ValueError):
        return jsonify({'error': 'rate_of_day must be a valid number'}), 400
    
    currency = data['currency'].upper()
    if currency not in ['USD', 'ZWG']:
        return jsonify({'error': 'Currency must be USD or ZWG'}), 400
    
    amount_usd = None
    amount_zwg = None
    
    # Calculate amounts with rounding to 2 decimal places
    if currency == 'USD':
        amount_usd = round(amount, 2)
        amount_zwg = round(amount * rate_of_day, 2)
    else:  # ZWG
        amount_zwg = round(amount, 2)
        amount_usd = round(amount / rate_of_day, 2) if rate_of_day else None
    
    # Validate the calculated amounts don't exceed database limits
    if amount_usd and amount_usd > 9999999.99:
        return jsonify({'error': 'Calculated USD amount exceeds maximum allowed value'}), 400
    if amount_zwg and amount_zwg > 9999999.99:
        return jsonify({'error': 'Calculated ZWG amount exceeds maximum allowed value'}), 400
    
    payment = Payment(
        student_id=student_id,
        receipt_number=receipt_number,
        amount=amount,
        currency=currency,
        rate_of_day=rate_of_day,
        amount_usd=amount_usd,
        amount_zwg=amount_zwg,
        payment_method=data['payment_method'],
        transaction_reference=data.get('transaction_reference'),
        notes=data.get('notes')
    )
    
    db.session.add(payment)
    db.session.commit()
    
    return jsonify(payment.to_dict()), 201


@app.route('/api/v1/students/<int:student_id>/arrears', methods=['GET'])
@jwt_required()
def get_student_arrears(student_id):
    total_fees = db.session.query(func.sum(Fee.amount_usd)).filter(Fee.student_id == student_id).scalar() or 0
    total_payments = db.session.query(func.sum(Payment.amount_usd)).filter(Payment.student_id == student_id).scalar() or 0
    
    arrears_usd = total_fees - total_payments
    
    return jsonify({
        'student_id': student_id,
        'total_fees_usd': float(total_fees),
        'total_payments_usd': float(total_payments),
        'arrears_usd': float(max(0, arrears_usd))
    }), 200

# ==================== GRADES & ACADEMICS ====================

@app.route('/api/v1/subjects', methods=['GET'])
@jwt_required()
def get_subjects():
    subjects = Subject.query.all()
    return jsonify([s.to_dict() for s in subjects]), 200

@app.route('/api/v1/grades', methods=['POST'])
@role_required(['developer', 'principal', 'teacher'])
def create_grade():
    data = request.get_json()
    
    required = ['student_id', 'subject_id', 'term_id', 'score']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400
    
    grade = Grade(
        student_id=data['student_id'],
        subject_id=data['subject_id'],
        term_id=data['term_id'],
        exam_type=data.get('exam_type'),
        score=data['score'],
        grade=calculate_grade(data['score']),
        remarks=data.get('remarks')
    )
    
    db.session.add(grade)
    db.session.commit()
    
    return jsonify(grade.to_dict()), 201

def calculate_grade(score):
    if score is None:
        return None
    if score >= 80:
        return 'A'
    elif score >= 70:
        return 'B'
    elif score >= 60:
        return 'C'
    elif score >= 50:
        return 'D'
    else:
        return 'E'

@app.route('/api/v1/students/<int:student_id>/report', methods=['GET'])
@jwt_required()
def get_student_report(student_id):
    student = Student.query.get_or_404(student_id)
    term_id = request.args.get('term_id')
    
    grades_query = Grade.query.filter_by(student_id=student_id)
    if term_id:
        grades_query = grades_query.filter_by(term_id=term_id)
    
    grades = grades_query.all()
    
    attendance_query = Attendance.query.filter_by(student_id=student_id)
    if term_id:
        term = Term.query.get(term_id)
        if term:
            attendance_query = attendance_query.filter(
                Attendance.date.between(term.start_date, term.end_date)
            )
    
    attendance = attendance_query.all()
    
    return jsonify({
        'student': student.to_dict(),
        'grades': [g.to_dict() for g in grades],
        'attendance': [a.to_dict() for a in attendance],
        'summary': {
            'average_grade': calculate_average(grades),
            'attendance_rate': calculate_attendance_rate(attendance)
        }
    }), 200

def calculate_average(grades):
    if not grades:
        return None
    scores = [g.score for g in grades if g.score is not None]
    if not scores:
        return None
    return sum(scores) / len(scores)

def calculate_attendance_rate(attendance):
    if not attendance:
        return 100
    present = sum(1 for a in attendance if a.status == 'present')
    return (present / len(attendance)) * 100

# ==================== ATTENDANCE ====================

@app.route('/api/v1/attendance', methods=['POST'])
@role_required(['developer', 'principal', 'teacher'])
def mark_attendance():
    data = request.get_json()
    
    required = ['student_id', 'date', 'status']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400
    
    attendance = Attendance(
        student_id=data['student_id'],
        date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
        status=data['status'],
        subject_id=data.get('subject_id'),
        remarks=data.get('remarks')
    )
    
    db.session.add(attendance)
    db.session.commit()
    
    return jsonify(attendance.to_dict()), 201

@app.route('/api/v1/attendance/class/<class_name>', methods=['GET'])
@jwt_required()
def get_class_attendance(class_name):
    date = request.args.get('date')
    if not date:
        return jsonify({'error': 'Date parameter required'}), 400
    
    date_obj = datetime.strptime(date, '%Y-%m-%d').date()
    
    students = Student.query.filter_by(class_name=class_name, is_active=True).all()
    attendance_records = Attendance.query.filter_by(date=date_obj).all()
    
    result = []
    for student in students:
        record = next((a for a in attendance_records if a.student_id == student.id), None)
        result.append({
            'student': student.to_dict(),
            'attendance': record.to_dict() if record else None
        })
    
    return jsonify(result), 200

# ==================== STOCK MANAGEMENT ====================

@app.route('/api/v1/stock', methods=['GET'])
@jwt_required()
def get_stock():
    category = request.args.get('category')
    query = StockItem.query
    if category:
        query = query.filter_by(category=category)
    
    items = query.all()
    return jsonify([i.to_dict() for i in items]), 200

@app.route('/api/v1/stock', methods=['POST'])
@role_required(['developer', 'principal'])
def create_stock_item():
    data = request.get_json()
    
    if not data.get('name'):
        return jsonify({'error': 'Item name is required'}), 400
    
    item = StockItem(
        name=data['name'],
        category=data.get('category'),
        quantity=data.get('quantity', 0),
        unit_price=data.get('unit_price'),
        currency=data.get('currency'),
        reorder_level=data.get('reorder_level', 10)
    )
    
    db.session.add(item)
    db.session.commit()
    
    return jsonify(item.to_dict()), 201

@app.route('/api/v1/stock/<int:item_id>', methods=['PUT'])
@role_required(['developer', 'principal'])
def update_stock(item_id):
    item = StockItem.query.get_or_404(item_id)
    data = request.get_json()
    
    if 'quantity' in data:
        item.quantity = data['quantity']
    if 'unit_price' in data:
        item.unit_price = data['unit_price']
    if 'reorder_level' in data:
        item.reorder_level = data['reorder_level']
    
    item.last_updated = datetime.utcnow()
    db.session.commit()
    
    return jsonify(item.to_dict()), 200

# ==================== SPORTS MANAGEMENT ====================

@app.route('/api/v1/sports', methods=['GET'])
@jwt_required()
def get_sports():
    sports = Sport.query.all()
    return jsonify([s.to_dict() for s in sports]), 200

@app.route('/api/v1/sports', methods=['POST'])
@role_required(['developer', 'principal'])
def create_sport():
    data = request.get_json()
    
    if not data.get('name'):
        return jsonify({'error': 'Sport name is required'}), 400
    
    sport = Sport(
        name=data['name'],
        coach_id=data.get('coach_id'),
        season=data.get('season'),
        venue=data.get('venue')
    )
    
    db.session.add(sport)
    db.session.commit()
    
    return jsonify(sport.to_dict()), 201

@app.route('/api/v1/sports/<int:sport_id>/register', methods=['POST'])
@jwt_required()
def register_sport(sport_id):
    data = request.get_json()
    
    if not data.get('student_id'):
        return jsonify({'error': 'student_id is required'}), 400
    
    # Check if already registered
    existing = SportRegistration.query.filter_by(
        student_id=data['student_id'],
        sport_id=sport_id
    ).first()
    
    if existing:
        return jsonify({'error': 'Student already registered for this sport'}), 400
    
    registration = SportRegistration(
        student_id=data['student_id'],
        sport_id=sport_id,
        position=data.get('position')
    )
    
    db.session.add(registration)
    db.session.commit()
    
    return jsonify(registration.to_dict()), 201

@app.route('/api/v1/sports/students/<int:student_id>', methods=['GET'])
@jwt_required()
def get_student_sports(student_id):
    registrations = SportRegistration.query.filter_by(student_id=student_id).all()
    return jsonify([r.to_dict() for r in registrations]), 200

# ==================== DASHBOARD & REPORTS ====================

@app.route('/api/v1/dashboard/summary', methods=['GET'])
@jwt_required()
def get_dashboard_summary():
    total_students = Student.query.filter_by(is_active=True).count()
    total_teachers = Teacher.query.filter_by(is_active=True).count()
    total_fees_usd = db.session.query(func.sum(Fee.amount_usd)).scalar() or 0
    total_payments_usd = db.session.query(func.sum(Payment.amount_usd)).scalar() or 0
    
    students_by_class = db.session.query(
        Student.class_name, func.count(Student.id)
    ).filter_by(is_active=True).group_by(Student.class_name).all()
    
    recent_payments = Payment.query.order_by(Payment.payment_date.desc()).limit(10).all()
    
    return jsonify({
        'total_students': total_students,
        'total_teachers': total_teachers,
        'total_revenue_usd': float(total_payments_usd),
        'total_fees_usd': float(total_fees_usd),
        'outstanding_fees_usd': float(total_fees_usd - total_payments_usd),
        'students_by_class': [{'class': c or 'Not Assigned', 'count': count} for c, count in students_by_class],
        'recent_payments': [p.to_dict() for p in recent_payments]
    }), 200

@app.route('/api/v1/dashboard/student/<int:student_id>', methods=['GET'])
@jwt_required()
def get_student_dashboard(student_id):
    student = Student.query.get_or_404(student_id)
    current_term = Term.query.filter_by(is_current=True).first()
    
    fees = Fee.query.filter_by(student_id=student_id).all()
    payments = Payment.query.filter_by(student_id=student_id).all()
    
    grades = []
    attendance = []
    
    if current_term:
        grades = Grade.query.filter_by(student_id=student_id, term_id=current_term.id).all()
        attendance = Attendance.query.filter(
            Attendance.student_id == student_id,
            Attendance.date.between(current_term.start_date, current_term.end_date)
        ).all()
    
    return jsonify({
        'student': student.to_dict(),
        'financial_summary': {
            'total_fees_usd': sum(f.amount_usd or 0 for f in fees),
            'total_payments_usd': sum(p.amount_usd or 0 for p in payments),
            'balance_usd': sum(f.amount_usd or 0 for f in fees) - sum(p.amount_usd or 0 for p in payments)
        },
        'current_term': current_term.to_dict() if current_term else None,
        'grades': [g.to_dict() for g in grades],
        'attendance_rate': calculate_attendance_rate(attendance)
    }), 200

# Root endpoint
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'School Management System API',
        'version': '1.0',
        'status': 'running',
        'endpoints': {
            'auth': '/api/v1/auth/login',
            'students': '/api/v1/students',
            'teachers': '/api/v1/teachers',
            'fees': '/api/v1/fees',
            'payments': '/api/v1/payments',
            'subjects': '/api/v1/subjects',
            'grades': '/api/v1/grades',
            'attendance': '/api/v1/attendance',
            'stock': '/api/v1/stock',
            'sports': '/api/v1/sports',
            'dashboard': '/api/v1/dashboard/summary'
        }
    }), 200


# ==================== EXCHANGE RATE MANAGEMENT ====================

@app.route('/api/v1/exchange-rates', methods=['GET'])
@jwt_required()
def get_exchange_rates():
    rates = ExchangeRate.query.order_by(ExchangeRate.effective_date.desc()).limit(10).all()
    return jsonify([r.to_dict() for r in rates]), 200

@app.route('/api/v1/exchange-rates/current', methods=['GET'])
@jwt_required()
def get_current_exchange_rate():
    current_rate = ExchangeRate.query.filter(
        ExchangeRate.effective_date <= datetime.now().date()
    ).order_by(ExchangeRate.effective_date.desc()).first()
    
    if not current_rate:
        return jsonify({'rate': 1.0, 'message': 'Default rate 1.0'}), 200
    
    return jsonify(current_rate.to_dict()), 200

@app.route('/api/v1/exchange-rates', methods=['POST'])
@role_required(['developer', 'principal'])
def set_exchange_rate():
    data = request.get_json()
    
    if not data.get('rate') or not data.get('effective_date'):
        return jsonify({'error': 'Rate and effective date are required'}), 400
    
    rate = ExchangeRate(
        rate=data['rate'],
        effective_date=datetime.strptime(data['effective_date'], '%Y-%m-%d').date(),
        set_by=get_jwt_identity(),
        notes=data.get('notes')
    )
    
    db.session.add(rate)
    db.session.commit()
    
    return jsonify(rate.to_dict()), 201

# ==================== TIMETABLE MANAGEMENT ====================

@app.route('/api/v1/timetable', methods=['GET'])
@jwt_required()
def get_timetable():
    class_name = request.args.get('class')
    day = request.args.get('day')
    term_id = request.args.get('term_id')
    
    query = Timetable.query
    if class_name:
        query = query.filter_by(class_name=class_name)
    if day:
        query = query.filter_by(day_of_week=day)
    if term_id:
        query = query.filter_by(term_id=term_id)
    
    timetable = query.order_by(Timetable.start_time).all()
    return jsonify([t.to_dict() for t in timetable]), 200

@app.route('/api/v1/timetable', methods=['POST'])
@role_required(['developer', 'principal', 'teacher'])
def add_timetable_entry():
    data = request.get_json()
    
    required = ['class_name', 'subject_id', 'teacher_id', 'day_of_week', 'start_time', 'end_time', 'term_id']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400
    
    entry = Timetable(
        class_name=data['class_name'],
        subject_id=data['subject_id'],
        teacher_id=data['teacher_id'],
        day_of_week=data['day_of_week'],
        start_time=datetime.strptime(data['start_time'], '%H:%M').time(),
        end_time=datetime.strptime(data['end_time'], '%H:%M').time(),
        room=data.get('room'),
        term_id=data['term_id']
    )
    
    db.session.add(entry)
    db.session.commit()
    
    return jsonify(entry.to_dict()), 201

@app.route('/api/v1/timetable/<int:entry_id>', methods=['DELETE'])
@role_required(['developer', 'principal'])
def delete_timetable_entry(entry_id):
    entry = Timetable.query.get_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()
    return jsonify({'message': 'Timetable entry deleted'}), 200

# ==================== EXAM RESULTS (ZIMSEC) ====================

@app.route('/api/v1/exam-results', methods=['POST'])
@role_required(['developer', 'principal', 'teacher'])
def add_exam_result():
    data = request.get_json()
    
    required = ['student_id', 'subject_id', 'term_id', 'score', 'exam_type']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400
    
    # Convert and validate score
    try:
        score = float(data['score'])
        if score < 0 or score > 100:
            return jsonify({'error': 'Score must be between 0 and 100'}), 400
    except (TypeError, ValueError):
        return jsonify({'error': 'Score must be a valid number'}), 400
    
    # Calculate ZIMSEC grade and points
    zimsec_grade, points = calculate_zimsec_grade(score)
    
    # Check if result already exists for this student, subject, term, and exam type
    existing = ExamResult.query.filter_by(
        student_id=data['student_id'],
        subject_id=data['subject_id'],
        term_id=data['term_id'],
        exam_type=data['exam_type']
    ).first()
    
    if existing:
        return jsonify({'error': 'Result already exists for this student, subject, term, and exam type'}), 400
    
    result = ExamResult(
        student_id=data['student_id'],
        subject_id=data['subject_id'],
        term_id=data['term_id'],
        exam_type=data['exam_type'],
        score=score,
        zimsec_grade=zimsec_grade,
        points=points,
        remarks=data.get('remarks'),
        entered_by=get_jwt_identity()
    )
    
    db.session.add(result)
    db.session.commit()
    
    return jsonify(result.to_dict()), 201


def calculate_zimsec_grade(score):
    """ZIMSEC Grading System"""
    if score >= 80:
        return 'A', 10
    elif score >= 70:
        return 'B', 8
    elif score >= 60:
        return 'C', 6
    elif score >= 50:
        return 'D', 4
    elif score >= 40:
        return 'E', 2
    else:
        return 'F', 0

@app.route('/api/v1/students/<int:student_id>/zimsec-report', methods=['GET'])
@jwt_required()
def get_zimsec_report(student_id):
    term_id = request.args.get('term_id')
    
    query = ExamResult.query.filter_by(student_id=student_id)
    if term_id:
        query = query.filter_by(term_id=term_id)
    
    results = query.all()
    
    # Calculate aggregates
    total_points = sum(r.points or 0 for r in results)
    subjects_count = len(results)
    average_points = total_points / subjects_count if subjects_count > 0 else 0
    
    return jsonify({
        'student_id': student_id,
        'term_id': term_id,
        'results': [r.to_dict() for r in results],
        'summary': {
            'total_points': total_points,
            'subjects_count': subjects_count,
            'average_points': round(average_points, 2),
            'performance': get_zimsec_performance(total_points, subjects_count)
        }
    }), 200

def get_zimsec_performance(total_points, subjects_count):
    if subjects_count == 0:
        return 'No Data'
    average = total_points / subjects_count
    if average >= 8:
        return 'Outstanding'
    elif average >= 6:
        return 'Good'
    elif average >= 4:
        return 'Satisfactory'
    elif average >= 2:
        return 'Below Average'
    else:
        return 'Poor'

# ==================== PAYMENT PLANS ====================

from dateutil.relativedelta import relativedelta

@app.route('/api/v1/payment-plans', methods=['GET'])
@jwt_required()
def get_all_payment_plans():
    """Get all payment plans with optional filters"""
    status = request.args.get('status')  # active, completed, defaulted
    
    query = PaymentPlan.query
    
    if status:
        query = query.filter_by(status=status)
    
    plans = query.order_by(PaymentPlan.created_at.desc()).all()
    return jsonify([plan.to_dict() for plan in plans]), 200

@app.route('/api/v1/payment-plans', methods=['POST'])
@role_required(['developer', 'principal'])
def create_payment_plan():
    data = request.get_json()
    
    required = ['student_id', 'total_amount', 'currency', 'installment_amount', 'number_of_installments', 'start_date']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400
    
    # Convert student_id to integer
    try:
        student_id = int(data['student_id'])
    except (TypeError, ValueError):
        return jsonify({'error': 'student_id must be a valid integer'}), 400
    
    # Convert numeric values to appropriate types
    try:
        total_amount = float(data['total_amount'])
        installment_amount = float(data['installment_amount'])
        number_of_installments = int(data['number_of_installments'])
    except (TypeError, ValueError) as e:
        return jsonify({'error': f'Invalid numeric value: {str(e)}'}), 400
    
    # Validate number_of_installments is positive
    if number_of_installments <= 0:
        return jsonify({'error': 'number_of_installments must be greater than 0'}), 400
    
    # Parse start_date
    try:
        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'start_date must be in YYYY-MM-DD format'}), 400
    
    # Calculate end date using actual month increments
    end_date = start_date + relativedelta(months=number_of_installments)
    
    # Validate currency
    currency = data['currency'].upper()
    if currency not in ['USD', 'ZWG']:
        return jsonify({'error': 'Currency must be USD or ZWG'}), 400
    
    # Optional: Validate that total_amount equals installment_amount * number_of_installments
    calculated_total = installment_amount * number_of_installments
    if abs(calculated_total - total_amount) > 0.01:
        return jsonify({
            'error': f'Total amount ({total_amount}) does not match installment_amount ({installment_amount}) × number_of_installments ({number_of_installments}) = {calculated_total}'
        }), 400
    
    plan = PaymentPlan(
        student_id=student_id,
        total_amount=total_amount,
        currency=currency,
        installment_amount=installment_amount,
        number_of_installments=number_of_installments,
        start_date=start_date,
        end_date=end_date,
        next_payment_date=start_date
    )
    
    db.session.add(plan)
    db.session.commit()
    
    return jsonify(plan.to_dict()), 201


@app.route('/api/v1/students/<int:student_id>/payment-plans', methods=['GET'])
@jwt_required()
def get_student_payment_plans(student_id):
    plans = PaymentPlan.query.filter_by(student_id=student_id).all()
    return jsonify([p.to_dict() for p in plans]), 200

# ==================== CLUB MANAGEMENT ====================

@app.route('/api/v1/clubs', methods=['GET'])
@jwt_required()
def get_clubs():
    clubs = Club.query.all()
    return jsonify([c.to_dict() for c in clubs]), 200

@app.route('/api/v1/clubs', methods=['POST'])
@role_required(['developer', 'principal'])
def create_club():
    data = request.get_json()
    
    club = Club(
        name=data['name'],
        category=data.get('category'),
        patron_name=data.get('patron_name'),
        meeting_day=data.get('meeting_day'),
        meeting_time=datetime.strptime(data['meeting_time'], '%H:%M').time() if data.get('meeting_time') else None,
        venue=data.get('venue'),
        description=data.get('description')
    )
    
    db.session.add(club)
    db.session.commit()
    
    return jsonify(club.to_dict()), 201

@app.route('/api/v1/clubs/<int:club_id>/register', methods=['POST'])
@jwt_required()
def register_for_club(club_id):
    data = request.get_json()
    
    existing = ClubMembership.query.filter_by(
        student_id=data['student_id'],
        club_id=club_id
    ).first()
    
    if existing:
        return jsonify({'error': 'Student already registered for this club'}), 400
    
    membership = ClubMembership(
        student_id=data['student_id'],
        club_id=club_id,
        role=data.get('role', 'member')
    )
    
    db.session.add(membership)
    db.session.commit()
    
    return jsonify(membership.to_dict()), 201

@app.route('/api/v1/students/<int:student_id>/clubs', methods=['GET'])
@jwt_required()
def get_student_clubs(student_id):
    memberships = ClubMembership.query.filter_by(student_id=student_id).all()
    return jsonify([m.to_dict() for m in memberships]), 200

@app.route('/api/v1/clubs/<int:club_id>/members', methods=['GET'])
@jwt_required()
def get_club_members(club_id):
    """Get all members of a specific club"""
    memberships = ClubMembership.query.filter_by(club_id=club_id, is_active=True).all()
    return jsonify([m.to_dict() for m in memberships]), 200

@app.route('/api/v1/clubs/<int:club_id>/members/<int:student_id>', methods=['DELETE'])
@jwt_required()
def remove_club_member(club_id, student_id):
    """Remove a student from a club"""
    membership = ClubMembership.query.filter_by(
        club_id=club_id, 
        student_id=student_id
    ).first()
    
    if not membership:
        return jsonify({'error': 'Membership not found'}), 404
    
    db.session.delete(membership)
    db.session.commit()
    
    return jsonify({'message': 'Member removed successfully'}), 200

# ==================== SPORTS MATCHES & ACHIEVEMENTS ====================

@app.route('/api/v1/sports-matches', methods=['GET'])
@jwt_required()
def get_sports_matches():
    sport_id = request.args.get('sport_id')
    query = SportsMatch.query
    if sport_id:
        query = query.filter_by(sport_id=sport_id)
    
    matches = query.order_by(SportsMatch.match_date.desc()).all()
    return jsonify([m.to_dict() for m in matches]), 200

# @app.route('/api/v1/sports-matches', methods=['POST'])
# @role_required(['developer', 'principal', 'coach'])
# def add_match():
#     data = request.get_json()
    
#     required = ['sport_id', 'opponent', 'match_date']
#     for field in required:
#         if field not in data:
#             return jsonify({'error': f'Missing field: {field}'}), 400
    
#     match = SportsMatch(
#         sport_id=data['sport_id'],
#         opponent=data['opponent'],
#         match_date=datetime.strptime(data['match_date'], '%Y-%m-%dT%H:%M:%S'),
#         venue=data.get('venue'),
#         our_score=data.get('our_score'),
#         opponent_score=data.get('opponent_score'),
#         result=data.get('result'),
#         match_type=data.get('match_type', 'friendly'),
#         season=data.get('season'),
#         notes=data.get('notes')
#     )
    
#     db.session.add(match)
#     db.session.commit()
    
#     return jsonify(match.to_dict()), 201

@app.route('/api/v1/sports-matches', methods=['POST'])
@role_required(['developer', 'principal', 'coach'])
def add_match():
    data = request.get_json()
    
    required = ['sport_id', 'opponent', 'match_date']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400
    
    # Handle different date formats
    match_date_str = data['match_date']
    try:
        # Try with seconds first (YYYY-MM-DDTHH:MM:SS)
        match_date = datetime.strptime(match_date_str, '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        try:
            # Try without seconds (YYYY-MM-DDTHH:MM)
            match_date = datetime.strptime(match_date_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DDTHH:MM:SS or YYYY-MM-DDTHH:MM'}), 400
    
    match = SportsMatch(
        sport_id=int(data['sport_id']),
        opponent=data['opponent'],
        match_date=match_date,
        venue=data.get('venue'),
        our_score=int(data['our_score']) if data.get('our_score') else None,
        opponent_score=int(data['opponent_score']) if data.get('opponent_score') else None,
        result=data.get('result'),
        match_type=data.get('match_type', 'friendly'),
        season=data.get('season'),
        notes=data.get('notes')
    )
    
    db.session.add(match)
    db.session.commit()
    
    return jsonify(match.to_dict()), 201

@app.route('/api/v1/sports/leaderboard', methods=['GET'])
@jwt_required()
def get_sports_leaderboard():
    sport_id = request.args.get('sport_id')
    
    query = db.session.query(
        Student.id,
        Student.full_name,
        func.count(SportsAchievement.id).label('achievements_count')
    ).outerjoin(
        SportsAchievement, Student.id == SportsAchievement.student_id
    ).filter(
        SportsAchievement.sport_id == sport_id if sport_id else True
    ).group_by(
        Student.id
    ).order_by(
        func.count(SportsAchievement.id).desc()
    ).limit(20)
    
    results = query.all()
    
    return jsonify([{
        'student_id': r[0],
        'student_name': r[1],
        'achievements_count': r[2]
    } for r in results]), 200

@app.route('/api/v1/sports-achievements', methods=['POST'])
@role_required(['developer', 'principal', 'coach'])
def add_achievement():
    data = request.get_json()
    
    required = ['student_id', 'sport_id', 'title', 'date_awarded']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400
    
    achievement = SportsAchievement(
        student_id=data['student_id'],
        sport_id=data['sport_id'],
        achievement_type=data.get('achievement_type'),
        title=data['title'],
        description=data.get('description'),
        date_awarded=datetime.strptime(data['date_awarded'], '%Y-%m-%d').date(),
        level=data.get('level', 'school')
    )
    
    db.session.add(achievement)
    db.session.commit()
    
    return jsonify(achievement.to_dict()), 201

# ==================== COMMUNICATION (SMS/Email Simulation) ====================

# @app.route('/api/v1/communication/send', methods=['POST'])
# @role_required(['developer', 'principal', 'teacher'])
# def send_communication():
#     data = request.get_json()
    
#     required = ['recipient_type', 'message_type', 'subject', 'message']
#     for field in required:
#         if field not in data:
#             return jsonify({'error': f'Missing field: {field}'}), 400
    
#     # Simulate sending (in production, integrate with actual SMS/Email APIs)
#     recipients = []
    
#     if data['recipient_type'] == 'all_students':
#         students = Student.query.filter_by(is_active=True).all()
#         recipients = [{'id': s.id, 'name': s.full_name, 'phone': s.phone, 'email': s.guardian_email} for s in students]
#     elif data['recipient_type'] == 'class':
#         students = Student.query.filter_by(class_name=data['class_name'], is_active=True).all()
#         recipients = [{'id': s.id, 'name': s.full_name, 'phone': s.phone, 'email': s.guardian_email} for s in students]
#     elif data['recipient_type'] == 'specific':
#         recipients = [{'id': data['recipient_id'], 'name': data['recipient_name']}]
    
#     # Log communication (simulate sending)
#     logs = []
#     for recipient in recipients:
#         log = CommunicationLog(
#             recipient_type=data['recipient_type'],
#             recipient_id=recipient.get('id'),
#             recipient_name=recipient['name'],
#             recipient_phone=recipient.get('phone'),
#             recipient_email=recipient.get('email'),
#             message_type=data['message_type'],
#             subject=data['subject'],
#             message=data['message'],
#             status='sent',
#             delivery_report=f"Simulated {data['message_type']} sent"
#         )
#         db.session.add(log)
#         logs.append(log)
    
#     db.session.commit()
    
#     return jsonify({
#         'message': f"Communication sent to {len(recipients)} recipients",
#         'logs': [l.to_dict() for l in logs]
#     }), 200

# backend/app.py
from email_service import email_service

@app.route('/api/v1/communication/send', methods=['POST'])

@role_required(['developer', 'principal', 'teacher'])
def send_communication():
    data = request.get_json()
    
    required = ['recipient_type', 'subject', 'message']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400
    
    # Check if email is configured
    if not email_service.is_configured:
        return jsonify({
            'error': 'Email system not configured. Please contact system administrator.'
        }), 500
    
    recipients = []
    
    # Get recipients based on type
    if data['recipient_type'] == 'all_students':
        students = Student.query.filter_by(is_active=True).all()
        recipients = [{
            'id': s.id,
            'name': s.full_name,
            'email': s.guardian_email,
            'type': 'student'
        } for s in students if s.guardian_email]
        
    elif data['recipient_type'] == 'all_teachers':
        teachers = Teacher.query.filter_by(is_active=True).all()
        recipients = [{
            'id': t.id,
            'name': t.full_name,
            'email': t.email,
            'type': 'teacher'
        } for t in teachers if t.email]
        
    elif data['recipient_type'] == 'class':
        students = Student.query.filter_by(class_name=data['class_name'], is_active=True).all()
        recipients = [{
            'id': s.id,
            'name': s.full_name,
            'email': s.guardian_email,
            'type': 'student'
        } for s in students if s.guardian_email]
        
    elif data['recipient_type'] == 'specific':
        recipient_id_parts = data['recipient_id'].split('_')
        if len(recipient_id_parts) == 2:
            type_prefix, id_value = recipient_id_parts
            if type_prefix == 'student':
                student = Student.query.get(int(id_value))
                if student and student.guardian_email:
                    recipients = [{
                        'id': student.id,
                        'name': student.full_name,
                        'email': student.guardian_email,
                        'type': 'student'
                    }]
            elif type_prefix == 'teacher':
                teacher = Teacher.query.get(int(id_value))
                if teacher and teacher.email:
                    recipients = [{
                        'id': teacher.id,
                        'name': teacher.full_name,
                        'email': teacher.email,
                        'type': 'teacher'
                    }]
    
    if not recipients:
        return jsonify({'error': 'No valid recipients with email addresses found'}), 400
    
    # Send emails
    subject = data['subject']
    message = data['message']
    
    # Send emails individually to track success/failure
    results = []
    successful_emails = []
    
    for recipient in recipients:
        result = email_service.send_email(
            to_email=recipient['email'],
            subject=subject,
            message=message,
            to_name=recipient['name']
        )
        
        # Log communication
        log = CommunicationLog(
            recipient_type=data['recipient_type'],
            recipient_id=recipient['id'],
            recipient_name=recipient['name'],
            recipient_email=recipient['email'],
            message_type='email',
            subject=subject,
            message=message,
            status='sent' if result['success'] else 'failed',
            delivery_report=result.get('message', result.get('error', 'Unknown error'))
        )
        db.session.add(log)
        
        if result['success']:
            successful_emails.append(recipient['email'])
        results.append(result)
    
    db.session.commit()
    
    return jsonify({
        'message': f"Emails sent to {len(successful_emails)} of {len(recipients)} recipients",
        'successful_count': len(successful_emails),
        'failed_count': len(recipients) - len(successful_emails),
        'recipients': successful_emails[:10],  # Show first 10 successful recipients
        'details': results[:5]  # Show first 5 results
    }), 200

@app.route('/api/v1/communication/email-status', methods=['GET'])
@role_required(['developer', 'principal'])
def get_email_status():
    """Check email service configuration status"""
    return jsonify({
        'is_configured': email_service.is_configured,
        'smtp_server': email_service.config.SMTP_SERVER if email_service.is_configured else None,
        'from_email': email_service.config.FROM_EMAIL if email_service.is_configured else None,
        'from_name': email_service.config.FROM_NAME if email_service.is_configured else None,
        'max_emails_per_minute': email_service.config.MAX_EMAILS_PER_MINUTE
    }), 200

@app.route('/api/v1/communication/logs', methods=['GET'])
@jwt_required()
def get_communication_logs():
    logs = CommunicationLog.query.order_by(CommunicationLog.sent_at.desc()).limit(50).all()
    return jsonify([l.to_dict() for l in logs]), 200

# ==================== REPORTS & ANALYTICS ====================

# @app.route('/api/v1/reports/academic/<int:student_id>', methods=['GET'])
# @jwt_required()
# def generate_academic_report(student_id):
#     term_id = request.args.get('term_id')
    
#     results = ExamResult.query.filter_by(student_id=student_id)
#     attendance = Attendance.query.filter_by(student_id=student_id)
    
#     if term_id:
#         results = results.filter_by(term_id=term_id)
#         term = Term.query.get(term_id)
#         if term:
#             attendance = attendance.filter(
#                 Attendance.date.between(term.start_date, term.end_date)
#             )
    
#     results_data = [r.to_dict() for r in results.all()]
#     attendance_data = [a.to_dict() for a in attendance.all()]
    
#     # Generate report data
#     report = {
#         'student_id': student_id,
#         'generated_at': datetime.now().isoformat(),
#         'academic': {
#             'subjects': len(results_data),
#             'total_points': sum(r.get('points', 0) for r in results_data),
#             'average_score': sum(r.get('score', 0) for r in results_data) / len(results_data) if results_data else 0
#         },
#         'attendance': {
#             'total_days': len(attendance_data),
#             'present_days': sum(1 for a in attendance_data if a['status'] == 'present'),
#             'absent_days': sum(1 for a in attendance_data if a['status'] == 'absent'),
#             'attendance_rate': calculate_attendance_rate(attendance_data)
#         },
#         'results': results_data,
#         'attendance_records': attendance_data
#     }
    
#     return jsonify(report), 200

@app.route('/api/v1/reports/financial', methods=['GET'])
@role_required(['developer', 'principal'])
def generate_financial_report():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = Payment.query
    if start_date:
        query = query.filter(Payment.payment_date >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(Payment.payment_date <= datetime.strptime(end_date, '%Y-%m-%d'))
    
    payments = query.all()
    
    total_usd = sum(p.amount_usd or 0 for p in payments)
    total_zwg = sum(p.amount_zwg or 0 for p in payments)
    
    # Group by payment method
    by_method = {}
    for p in payments:
        method = p.payment_method or 'cash'
        by_method[method] = by_method.get(method, 0) + float(p.amount_usd or 0)
    
    return jsonify({
        'period': {'start_date': start_date, 'end_date': end_date},
        'total_collections_usd': total_usd,
        'total_collections_zwg': total_zwg,
        'total_transactions': len(payments),
        'breakdown_by_method': by_method,
        'recent_payments': [p.to_dict() for p in payments[:20]]
    }), 200

# @app.route('/api/v1/reports/sports-participation', methods=['GET'])
# @jwt_required()
# def get_sports_participation_report():
#     sport_id = request.args.get('sport_id')
    
#     query = db.session.query(
#         Sport.name,
#         func.count(SportRegistration.id).label('participants')
#     ).join(
#         SportRegistration, Sport.id == SportRegistration.sport_id
#     ).group_by(Sport.id)
    
#     if sport_id:
#         query = query.filter(Sport.id == sport_id)
    
#     results = query.all()
    
#     return jsonify([{
#         'sport': r[0],
#         'participants': r[1]
#     } for r in results]), 200

@app.route('/api/v1/reports/sports-participation', methods=['GET'])
@jwt_required()
def get_sports_participation_report():
    sport_id = request.args.get('sport_id')
    
    # Query to get sports with participant counts
    query = db.session.query(
        Sport.name.label('sport'),
        func.count(SportRegistration.id).label('participants')
    ).outerjoin(
        SportRegistration, Sport.id == SportRegistration.sport_id
    )
    
    if sport_id:
        query = query.filter(Sport.id == sport_id)
    
    results = query.group_by(Sport.id).order_by(func.count(SportRegistration.id).desc()).all()
    
    # Return empty array if no results
    return jsonify([{
        'sport': r[0],
        'participants': r[1] or 0
    } for r in results]), 200

@app.route('/api/v1/reports/export/<report_type>', methods=['GET'])
@jwt_required()
def export_report(report_type):
    """Generate CSV export of reports"""
    import csv
    from io import StringIO
    
    output = StringIO()
    
    if report_type == 'students':
        students = Student.query.filter_by(is_active=True).all()
        writer = csv.DictWriter(output, fieldnames=['id', 'full_name', 'national_id', 'class_name', 'stream', 'phone', 'guardian_name'])
        writer.writeheader()
        for s in students:
            writer.writerow({
                'id': s.id,
                'full_name': s.full_name,
                'national_id': s.national_id,
                'class_name': s.class_name,
                'stream': s.stream,
                'phone': s.phone,
                'guardian_name': s.guardian_name
            })
    
    elif report_type == 'fees':
        payments = Payment.query.all()
        writer = csv.DictWriter(output, fieldnames=['receipt_number', 'student_name', 'amount', 'currency', 'payment_method', 'payment_date'])
        writer.writeheader()
        for p in payments:
            writer.writerow({
                'receipt_number': p.receipt_number,
                'student_name': p.student.full_name if p.student else 'N/A',
                'amount': p.amount,
                'currency': p.currency,
                'payment_method': p.payment_method,
                'payment_date': p.payment_date.date()
            })
    
    else:
        return jsonify({'error': 'Invalid report type'}), 400
    
    return jsonify({
        'report_type': report_type,
        'data': output.getvalue(),
        'message': 'CSV data generated. In production, this would be a downloadable file.'
    }), 200

# ==================== Ministry Compliance Reporting ====================

@app.route('/api/v1/reports/ministry-compliance', methods=['GET'])
@role_required(['developer', 'principal'])
def ministry_compliance_report():
    year = request.args.get('year', datetime.now().year)
    
    # Get statistics for ministry reporting
    total_students = Student.query.filter_by(is_active=True).count()
    students_by_gender = db.session.query(
        Student.gender, func.count(Student.id)
    ).filter_by(is_active=True).group_by(Student.gender).all()
    
    students_by_class = db.session.query(
        Student.class_name, func.count(Student.id)
    ).filter_by(is_active=True).group_by(Student.class_name).all()
    
    total_teachers = Teacher.query.filter_by(is_active=True).count()
    
    # Get exam performance by subject
    exam_performance = db.session.query(
        Subject.name,
        func.avg(ExamResult.score).label('avg_score'),
        func.count(ExamResult.id).label('total_exams')
    ).join(ExamResult, Subject.id == ExamResult.subject_id).group_by(Subject.id).all()
    
    return jsonify({
        'school_name': 'Craft Cart School',
        'reporting_year': year,
        'report_date': datetime.now().isoformat(),
        'enrollment': {
            'total_students': total_students,
            'by_gender': [{'gender': g or 'Not specified', 'count': c} for g, c in students_by_gender],
            'by_class': [{'class': c, 'count': cnt} for c, cnt in students_by_class]
        },
        'staffing': {
            'total_teachers': total_teachers
        },
        'academic_performance': [
            {'subject': name, 'average_score': round(float(avg_score), 2) if avg_score else 0, 'total_exams': total}
            for name, avg_score, total in exam_performance
        ],
        'compliance_status': 'All data up to date'
    }), 200

def calculate_attendance_rate(attendance_data):
    """Calculate attendance rate from attendance records"""
    if not attendance_data:
        return 0.0
    total_days = len(attendance_data)
    present_days = sum(1 for a in attendance_data if a.get('status') == 'present')
    return (present_days / total_days * 100) if total_days > 0 else 0.0

@app.route('/api/v1/reports/academic/<int:student_id>', methods=['GET'])
@jwt_required()
def generate_academic_report(student_id):
    term_id = request.args.get('term_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    results_query = ExamResult.query.filter_by(student_id=student_id)
    attendance_query = Attendance.query.filter_by(student_id=student_id)
    
    if term_id:
        results_query = results_query.filter_by(term_id=term_id)
        term = Term.query.get(term_id)
        if term:
            attendance_query = attendance_query.filter(
                Attendance.date.between(term.start_date, term.end_date)
            )
    
    if start_date and end_date:
        start = datetime.strptime(start_date, '%Y-%m-%d').date()
        end = datetime.strptime(end_date, '%Y-%m-%d').date()
        attendance_query = attendance_query.filter(
            Attendance.date.between(start, end)
        )
    
    results_data = []
    for r in results_query.all():
        result_dict = r.to_dict()
        result_dict['subject'] = r.subject.name if r.subject else 'Unknown'
        results_data.append(result_dict)
    
    attendance_data = [a.to_dict() for a in attendance_query.all()]
    
    # Calculate attendance rate
    total_days = len(attendance_data)
    present_days = sum(1 for a in attendance_data if a.get('status') == 'present')
    attendance_rate = (present_days / total_days * 100) if total_days > 0 else 0
    
    total_points = sum(r.get('points', 0) for r in results_data)
    avg_score = sum(r.get('score', 0) for r in results_data) / len(results_data) if results_data else 0
    
    report = {
        'student_id': student_id,
        'generated_at': datetime.now().isoformat(),
        'academic': {
            'subjects': len(results_data),
            'total_points': total_points,
            'average_score': avg_score
        },
        'attendance': {
            'total_days': total_days,
            'present_days': present_days,
            'absent_days': total_days - present_days,
            'attendance_rate': attendance_rate
        },
        'results': results_data
    }
    
    return jsonify(report), 200



# ==================================== LINKS ==================================================

@app.route('/api/v1/users/link-student', methods=['POST'])
@role_required(['developer', 'principal'])
def link_student_to_user():
    data = request.get_json()
    
    student_id = data.get('student_id')
    user_id = data.get('user_id')
    
    student = Student.query.get_or_404(student_id)
    user = User.query.get_or_404(user_id)
    
    # Link student to user account
    student.user_id = user_id
    db.session.commit()
    
    return jsonify({
        'message': f'Student {student.full_name} linked to user {user.username}',
        'student_id': student_id,
        'user_id': user_id
    }), 200

@app.route('/api/v1/users/link-teacher', methods=['POST'])
@role_required(['developer', 'principal'])
def link_teacher_to_user():
    data = request.get_json()
    
    teacher_id = data.get('teacher_id')
    user_id = data.get('user_id')
    
    teacher = Teacher.query.get_or_404(teacher_id)
    user = User.query.get_or_404(user_id)
    
    # Link teacher to user account
    teacher.user_id = user_id
    
    # Update user role if not already teacher
    if user.role != 'teacher':
        user.role = 'teacher'
    
    db.session.commit()
    
    return jsonify({
        'message': f'Teacher {teacher.full_name} linked to user {user.username}',
        'teacher_id': teacher_id,
        'user_id': user_id
    }), 200



# ==========================================TEACEHR==================================
# ==================== TEACHER MANAGEMENT ====================

@app.route('/api/v1/teachers', methods=['GET'])
@jwt_required()
@role_required(['developer', 'principal', 'teacher'])
def get_teachers():
    """Get all teachers (filtered by role)"""
    user = request.current_user
    user_role = user.role
    
    query = Teacher.query.filter_by(is_active=True)
    
    # Teachers can only see themselves
    if user_role == 'teacher':
        teacher = Teacher.query.filter_by(user_id=user.id).first()
        if teacher:
            query = query.filter(Teacher.id == teacher.id)
    
    teachers = query.all()
    return jsonify([t.to_dict() for t in teachers]), 200


@app.route('/api/v1/teachers', methods=['POST'])
@role_required(['developer', 'principal'])
def create_teacher():
    """Create a new teacher"""
    data = request.get_json()
    
    # Validate required fields
    if not data.get('staff_id') or not data.get('full_name'):
        return jsonify({'error': 'Staff ID and full name are required'}), 400
    
    # Check if staff_id exists
    if Teacher.query.filter_by(staff_id=data['staff_id']).first():
        return jsonify({'error': 'Staff ID already exists'}), 400
    
    # Check if national_id exists (if provided)
    if data.get('national_id'):
        if Teacher.query.filter_by(national_id=data['national_id']).first():
            return jsonify({'error': 'Teacher with this national ID already exists'}), 400
    
    # Create teacher record
    teacher = Teacher(
        staff_id=data['staff_id'],
        full_name=data['full_name'],
        national_id=data.get('national_id'),
        phone=data.get('phone'),
        email=data.get('email'),
        subjects=','.join(data['subjects']) if isinstance(data.get('subjects'), list) else data.get('subjects'),
        classes_assigned=','.join(data['classes_assigned']) if isinstance(data.get('classes_assigned'), list) else data.get('classes_assigned'),
        qualification=data.get('qualification'),
        hire_date=datetime.strptime(data['hire_date'], '%Y-%m-%d').date() if data.get('hire_date') else datetime.now().date()
    )
    
    db.session.add(teacher)
    db.session.commit()
    
    return jsonify(teacher.to_dict()), 201


@app.route('/api/v1/teachers/<int:teacher_id>', methods=['GET'])
@jwt_required()
@role_required(['developer', 'principal', 'teacher'])
def get_teacher(teacher_id):
    """Get a specific teacher by ID"""
    user = request.current_user
    teacher = Teacher.query.get_or_404(teacher_id)
    
    # Teachers can only see themselves
    if user.role == 'teacher':
        user_teacher = Teacher.query.filter_by(user_id=user.id).first()
        if user_teacher and user_teacher.id != teacher_id:
            return jsonify({'error': 'You can only view your own profile'}), 403
    
    return jsonify(teacher.to_dict()), 200


@app.route('/api/v1/teachers/<int:teacher_id>', methods=['PUT'])
@role_required(['developer', 'principal'])
def update_teacher(teacher_id):
    """Update a teacher's information"""
    teacher = Teacher.query.get_or_404(teacher_id)
    data = request.get_json()
    
    # Update fields
    updatable_fields = ['full_name', 'phone', 'email', 'qualification']
    for field in updatable_fields:
        if field in data:
            setattr(teacher, field, data[field])
    
    # Handle subjects (comma-separated)
    if 'subjects' in data:
        teacher.subjects = ','.join(data['subjects']) if isinstance(data['subjects'], list) else data['subjects']
    
    # Handle classes assigned
    if 'classes_assigned' in data:
        teacher.classes_assigned = ','.join(data['classes_assigned']) if isinstance(data['classes_assigned'], list) else data['classes_assigned']
    
    # Handle hire date
    if 'hire_date' in data:
        teacher.hire_date = datetime.strptime(data['hire_date'], '%Y-%m-%d').date()
    
    db.session.commit()
    return jsonify(teacher.to_dict()), 200


@app.route('/api/v1/teachers/<int:teacher_id>', methods=['DELETE'])
@role_required(['developer', 'principal'])
def delete_teacher(teacher_id):
    """Deactivate a teacher (soft delete)"""
    teacher = Teacher.query.get_or_404(teacher_id)
    teacher.is_active = False
    db.session.commit()
    return jsonify({'message': 'Teacher deactivated successfully'}), 200


@app.route('/api/v1/teachers/<int:teacher_id>/reactivate', methods=['POST'])
@role_required(['developer', 'principal'])
def reactivate_teacher(teacher_id):
    """Re-activate a teacher"""
    teacher = Teacher.query.get_or_404(teacher_id)
    teacher.is_active = True
    db.session.commit()
    return jsonify({'message': 'Teacher reactivated successfully'}), 200


# ======================================== LINK ===================================================

@app.route('/api/v1/terms', methods=['GET'])
@jwt_required()
def get_terms():
    terms = Term.query.order_by(Term.year.desc(), Term.term_number).all()
    return jsonify([t.to_dict() for t in terms]), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)