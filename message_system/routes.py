from flask import url_for, flash, redirect, request, abort
from message_system import app, bcrypt, db
from message_system.models import User, Message
from flask_login import login_user, current_user


@app.route("/")
@app.route("/home")
def home():
   return str(Message.query.all())

@app.route("/signin", methods=['GET', 'POST'])
def signin():
    args = request.args
    password = args.get("password")
    username = args.get("username")
    # if current_user.is_authenticated:
    #     return redirect(url_for('home'))
    hashed_password = bcrypt.generate_password_hash(password).decode('utf8')
    user = User(username=username, password=hashed_password)
    user_check = User.query.filter_by(username=username).first()
    if user_check:
        return "Existing username, please choose a different one."
    else:
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    args = request.args
    password = args.get("password")
    username = args.get("username")
    # if current_user.is_authenticated:
    #     return redirect(url_for('home'))
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        return redirect(url_for('home'))
    else:
        return "failed to login. Try again"


@app.route("/write_message")
def write_message():
    args = request.args
    receiver = args.get("receiver")
    subject = args.get("subject")
    message_content = args.get("message_content")
    # creation_date = args.get("creation_date")

    receiver_user = User.query.filter_by(username=receiver).first()
    if receiver_user:
        message = Message(receiver=receiver, subject=subject, message_content=message_content, sender=current_user)
        db.session.add(message)
        db.session.commit()
        return redirect(url_for('home'))
    else:
        return "You need to choose existing user to send the message"

@app.route("/user/<string:username>")
def user_messages(username):
    user = User.query.filter_by(username=username).first_or_404()
    messages = Message.query.filter_by(receiver=user.username).order_by(Message.creation_date.desc())
    return str(messages.all())

@app.route("/user/unread_messages/<string:username>")
def user_unread_messages(username):
    user = User.query.filter_by(username=username).first_or_404()
    messages = Message.query.filter_by(receiver=user.username, is_read=False).order_by(Message.creation_date.desc())
    return str(messages.all())

@app.route("/message/<int:message_id>")
def message(message_id):
    args = request.args
    delete = args.get("delete")
    message = Message.query.get_or_404(message_id)
    message.is_read = True
    db.session.commit()
    if delete=='Yes':
        if message.sender != current_user and message.receiver != current_user.username:
            abort(403)
        else:
            db.session.delete(message)
            db.session.commit()
            return "The message has been deleted"

    return str(message)





