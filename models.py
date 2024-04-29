from application import db

user_subject = db.Table(
    'user_subject',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('subject_id', db.Integer, db.ForeignKey('subject.id'), primary_key=True),
    extend_existing=True
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    role = db.Column(db.String(50), nullable=False, default='student')
    subjects = db.relationship("Subject", secondary=user_subject, back_populates="users")

    def __repr__(self):
        return f'<User {self.email}>'

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)  # Make email field unique
    phone_number = db.Column(db.String(20))
    profile_picture = db.Column(db.String(200))
    classes_tutoring = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='profile')

    def __repr__(self):
        return f'<Profile {self.email}>'
    
class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    users = db.relationship("User", secondary=user_subject, back_populates="subjects")

    def __repr__(self):
        return f'<Subject {self.name}>'
