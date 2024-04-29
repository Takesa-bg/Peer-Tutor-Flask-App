from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, EqualTo, Regexp
from models import db, User
from models import Profile
import requests
from flask import jsonify
from collections import defaultdict
from flask_wtf.file import FileField
from wtforms import TextAreaField


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize SQLAlchemy with the Flask app
db.init_app(app)

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[
        InputRequired(),
        Length(min=8, message='Password must be at least 8 characters long'),
        Regexp(
            regex=r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]*$',
            message='Password must contain at least one uppercase letter, one lowercase letter, and one special character'
        )
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        InputRequired(), EqualTo('password', message='Passwords must match')
    ])
    first_name = StringField('First Name', validators=[InputRequired()])
    last_name = StringField('Last Name', validators=[InputRequired()])
    role = StringField('Role', validators=[InputRequired(), Regexp('^(admin|tutor|student)$', message='Invalid role')])
    submit = SubmitField('Register')

JOTFORM_API_KEY = '371e60574454072c9cd4b20527f7af2f'
JOTFORM_FORM_ID = '72324578307156'

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class ProfileForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired(), Email()])
    phone_number = StringField('Phone Number')
    profile_picture = StringField('Profile Picture')
    submit = SubmitField('Submit')

class EditProfileForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired(), Email()])
    phone_number = StringField('Phone Number')
    profile_picture = FileField('Profile Picture')
    classes_tutoring = TextAreaField('Classes Tutoring', validators=[InputRequired()])
    submit = SubmitField('Save Changes')


@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if the email ends with "@email.msmary.edu"
        if not form.email.data.endswith('@email.msmary.edu'):
            flash('Please use an email ending with @email.msmary.edu', 'error')
            return redirect(url_for('register'))  # Redirect back to the registration page
            
        # Check if the email already exists in the database
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email address already exists. Please use a different email.', 'error')
            return redirect(url_for('register'))  # Redirect back to the registration page
            
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(email=form.email.data, password=hashed_password, first_name=form.first_name.data, last_name=form.last_name.data, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            # Authentication successful
            session['user_id'] = user.id
            session['user_role'] = user.role
            flash('Login successful!')

            # Check if the user is an admin
            if user.role == 'admin':
                session['admin_logged_in'] = True
                flash('Admin login successful!')
                return redirect(url_for('admin_dashboard'))
            else:
                if user.role == 'tutor':
                    return redirect(url_for('tutor_dashboard'))
                elif user.role == 'student':
                    return redirect(url_for('student_dashboard'))
        else:
            # Authentication failed
            flash('Invalid email or password. Please try again.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_role', None)
    flash('You have been logged out.')
    return redirect(url_for('welcome'))

@app.route('/fetch_jotform_submissions')
def fetch_jotform_submissions():
    url = f'https://api.jotform.com/form/{JOTFORM_FORM_ID}/submissions'
    headers = {'Authorization': f'Bearer {JOTFORM_API_KEY}'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        submissions_data = response.json().get('content')
        submissions = [submission['answers'] for submission in submissions_data]
        return jsonify(submissions=submissions)  # Return submissions data
    else:
        flash('Failed to fetch JotForm submissions.')
        return jsonify(submissions=[])

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return render_template('dashboard.html', first_name=user.first_name, role=user.role)
        else:
            flash('User not found. Please log in again.')
            return redirect(url_for('login'))
    else:
        flash('Please log in to access the dashboard.')
        return redirect(url_for('login'))

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' in session and 'user_role' in session and session['user_role'] == 'admin':
        # Fetch tutor profiles from the database
        profiles = Profile.query.all()

        # Fetch JotForm submissions (you need to implement this)
        submissions_response = fetch_jotform_submissions()
        submissions = submissions_response.json.get('submissions', [])

        # Match tutors to students
        assignments = match_tutors_to_students(profiles, submissions)

        return render_template('admin_dashboard.html', assignments=assignments)
    else:
        flash('You do not have permission to access the admin dashboard.')
        return redirect(url_for('welcome'))
    
def match_tutors_to_students(profiles, submissions):
    tutor_subjects = defaultdict(list)
    for profile in profiles:
        for subject in profile.classes_tutoring.split(','):
            tutor_subjects[subject.strip()].append(profile)

    assignments = []
    for submission in submissions:
        student_classes = submission.get('classes', '').split(',')
        preferred_times = submission.get('preferred_times', '')

        suitable_tutors = []
        for student_class in student_classes:
            suitable_tutors.extend(tutor_subjects.get(student_class.strip(), []))

        if suitable_tutors:
            assignments.append({'student': submission['student_name'], 'tutors': suitable_tutors})
    return assignments

@app.route('/users_table', methods=['GET', 'POST'])
def users_table():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        user = User.query.get(user_id)

        if user:
            if action == 'promote':
                user.role = 'admin'
                db.session.commit()
                flash('User has been promoted to admin successfully!')
            elif action == 'demote':
                user.role = 'user'
                db.session.commit()
                flash('Admin privileges removed successfully for this user!')
        else:
            flash('User not found!')

    users = User.query.all()
    return render_template('users_table.html', users=users)

@app.route('/student_dashboard')
def student_dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.role == 'student':
            return render_template('student_dashboard.html', user=user)
        else:
            flash('You do not have permission to access the student dashboard.')
            return redirect(url_for('welcome'))
    else:
        flash('Please log in to access the student dashboard.')
        return redirect(url_for('login'))

@app.route('/tutor_dashboard')
def tutor_dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.role == 'tutor':
            # Retrieve the user's profile
            profile = user.profile
            
            # Render the template with both user and profile data
            return render_template('tutor_dashboard.html', user=user, profile=profile)
        else:
            flash('You do not have permission to access the tutor dashboard.')
    else:
        flash('Please log in to access the tutor dashboard.')
    return redirect(url_for('welcome'))

@app.route('/create_profile', methods=['GET', 'POST'])
def create_profile():
    if request.method == 'POST':
        user_id = session.get('user_id')
        user = User.query.get(user_id)
        if user:
            name = request.form['name']
            email = request.form['email']
            phone_number = request.form.get('phone_number')
            classes_tutoring = request.form['classes_tutoring']
            
            profile_picture_filename = None  # Initialize the variable
            
            # Handle profile picture upload
            if 'profile_picture' in request.files:
                profile_picture = request.files['profile_picture']
                if profile_picture.filename != '':
                    filename = secure_filename(profile_picture.filename)
                    profile_picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    profile_picture.save(profile_picture_path)
                    # Save the filename instead of database ID
                    profile_picture_filename = filename
            
            # Validate email address
            if not email.endswith('@email.msmary.edu'):
                flash('Email address must end with "@email.msmary.edu".')
                return redirect(url_for('create_profile'))

            new_profile = Profile(name=name, email=email, phone_number=phone_number,
                                  profile_picture=profile_picture_filename, classes_tutoring=classes_tutoring, user_id=user.id)
            db.session.add(new_profile)
            db.session.commit()
            flash('Profile created successfully!')
            return redirect(url_for('tutor_dashboard'))  # Redirect to tutor_dashboard upon successful profile creation
        else:
            flash('User not found. Please log in again.')
            return redirect(url_for('login'))
    return render_template('create_profile.html')

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    profile = user.profile
    form = EditProfileForm(obj=profile)  # Pass the profile object to populate the form
    if request.method == 'POST' and form.validate_on_submit():
        form.populate_obj(profile)  # Update the profile object with form data
        # Handle profile picture upload
        if 'profile_picture' in request.files:
            profile_picture = request.files['profile_picture']
            if profile_picture.filename != '':
                filename = secure_filename(profile_picture.filename)
                profile_picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                profile_picture.save(profile_picture_path)
                profile.profile_picture = filename  # Save the filename instead of database ID
        db.session.commit()
        flash('Profile updated successfully!')
        return redirect(url_for('tutor_dashboard'))
    return render_template('edit_profile.html', form=form, profile=profile)

if __name__ == '__main__':
    app.run(debug=False, port=1600)



