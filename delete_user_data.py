from app import app, db  # Assuming your Flask app instance is named app
from models import User  # Assuming User is your SQLAlchemy model

def delete_user_data():
    with app.app_context():  # Establish the application context
        try:
            # Delete all records from the User table
            db.session.query(User).delete()
            db.session.commit()
            print("All data deleted successfully.")
        except Exception as e:
            print(f"An error occurred: {e}")
            db.session.rollback()

if __name__ == "__main__":
    delete_user_data()




