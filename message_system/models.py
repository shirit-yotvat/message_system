from datetime import datetime
from message_system import db, login_manager, app
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#build User object
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    messages = db.relationship('Message', backref='sender', lazy=True)

    def __repr__(self):
        return str({"username": self.username})

#build Message object
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receiver = db.Column(db.String(10), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    message_content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    receiver_delete = db.Column(db.Boolean, default=False, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return str({"subject": self.subject, "content": self.message_content, "creation date": str(self.creation_date)})