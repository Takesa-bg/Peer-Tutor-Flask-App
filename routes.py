from flask import render_template, request, redirect, url_for, flash, session
from flask_project import app, db
from flask_project.models import User
from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        # Check if a user with the same email and role combination exists
        existing_user = User.query.filter_by(email=email, role=role).first()

        if existing_user:
            flash('An account with the same email and role already exists. Please use a different email or role.')
            return redirect(url_for('register'))

        # No unique constraint on email, so we don't need to check for existing users with the same email

        hashed_pwd = generate_password_hash(password)
        new_user = User(email=email, password=hashed_pwd, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_role'] = user.role
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid login credentials!')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        user = db.session.get(User, user_id)  # Use db.session.get() for SQLAlchemy 2.0 compatibility

        if user:
            # Pass the user's email and role to the template
            if user.role == 'admin':
                return render_template('admin_dashboard.html', username=user.email, role=user.role)
            elif user.role == 'tutor':
                return render_template('tutor_dashboard.html', username=user.email, role=user.role)
            elif user.role == 'student':
                return render_template('student_dashboard.html', username=user.email, role=user.role)
            else:
                # Default dashboard or error handling
                flash('Your role does not have a specific dashboard.')
                return redirect(url_for('welcome'))
        else:
            flash('User not found. Please log in again.')
            return redirect(url_for('login'))
    else:
        flash('Please log in to access the dashboard.')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('user_id', None) session.pop('user_role', None)
    flash('You have been logged out.')
    return redirect(url_for('welcome'))
