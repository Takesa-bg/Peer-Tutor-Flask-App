from application import app, db
from models import User
from werkzeug.security import generate_password_hash

def add_admin():
    try:
        with app.app_context():
            existing_admin = User.query.filter_by(email='admin@example.com').first()
            if existing_admin:
                print("Admin already exists.")
                return

            hashed_password = generate_password_hash('Admin123!', method='pbkdf2:sha256')

            # Provide values for first_name and last_name
            admin = User(email='admin@example.com', password=hashed_password, 
                         first_name='Admin', last_name='User', role='admin')
            db.session.add(admin)
            db.session.commit()
            print("Admin added successfully.")
    except Exception as e:
        print(f"Error adding admin: {e}")

if __name__ == '__main__':
    add_admin()
