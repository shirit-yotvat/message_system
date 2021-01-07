from flask import redirect, request, abort
from message_system import app, bcrypt, db
from message_system.models import User, Message
from flask_login import login_user, current_user, logout_user, login_required


#sign in to the app
#args: username(string)- must be not already in use.
#      password(int)
@app.route("/")
@app.route("/signin", methods=['GET', 'POST'])
def signin():
    if current_user.is_authenticated:
        return "You need to logout first"
    args = request.args
    password = args.get("password")
    username = args.get("username")
    try:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf8')
        user = User(username=username, password=hashed_password)
        user_check = User.query.filter_by(username=username).first()
        if user_check:
            return "Existing username, please choose a different one."
        else:
            db.session.add(user)
            db.session.commit()
            return "Success sign in!"
    except:
        return "Please sign in"

#log in to the app
#args: username(string)- must be existing user
#      password(int)
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return "You need to logout first"
    args = request.args
    password = args.get("password")
    username = args.get("username")

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        return "Success log in!"
    else:
        return "Wrong username or password, try again."

#log out from the app
@app.route("/logout")
def logout():
    logout_user()
    return "Success logout!"

#write a message
# args: receiver(string)- must be an existing user.
#       subject(string)
#       message_content(string)
@app.route("/user/write_message", methods=['GET', 'POST'])
@login_required
def write_message():
    if current_user.is_authenticated:
        args = request.args
        receiver = args.get("receiver")
        subject = args.get("subject")
        message_content = args.get("message_content")

        receiver_user = User.query.filter_by(username=receiver).first()
        if receiver_user:
            message = Message(receiver=receiver, subject=subject, message_content=message_content, sender=current_user)
            db.session.add(message)
            db.session.commit()
            return "Your message was sent!"
        else:
            return "You need to choose an existing user to send the message"

#return list of messages' IDs
#params: messages(list)
#return: lst_id(list)
def return_list_messages_id(messages):
    lst_id = []
    for message in messages:
        lst_id.append({'id': message.id})
    return str(lst_id)

#all messages' id for a specific user
@app.route("/user/<string:username>/all_messages_id")
@login_required
def get_user_messages_id(username):
    if current_user.username == username:
        messages = Message.query.filter_by(receiver=username, receiver_delete=False).order_by(Message.creation_date.desc())
        lst_id = return_list_messages_id(messages)
        return lst_id
    else:
        return "You can't enter to other user's messages"

#all unread messages' id for a specific user
@app.route("/user/<string:username>/all_unread_messages_id")
@login_required
def get_unread_messages_id(username):
    if current_user.username == username:
        messages = Message.query.filter_by(receiver=username, is_read=False, receiver_delete=False).order_by(Message.creation_date.desc())
        lst_id = return_list_messages_id(messages)
        return lst_id
    else:
        return "You can't enter to other user's messages"

#read one message
# args: delete(string)- optional, need to be 'Yes' for delete
@app.route("/user/<string:username>/<int:message_id>", methods=['GET', 'POST'])
@login_required
def get_message(message_id, username):
    args = request.args
    delete = args.get("delete")
    message = Message.query.filter_by(id=message_id).first()
    if message.receiver == current_user.username:
        if message.receiver_delete == True:
            return abort(403)
        message.is_read = True
        db.session.commit()
        if delete =='Yes':
            message.receiver_delete = True
            db.session.commit()
            return "The message has been deleted"
        return str(message)
    elif username == current_user.username:
        if delete=='Yes':
            db.session.delete(message)
            db.session.commit()
            return "The message has been deleted"
        return str(message)
    else:
        return "You can't enter to other user's messages"

#all sent messages' id for a specific user
@app.route("/user/<string:username>/all_sent_messages_id")
@login_required
def get_sent_messages_id(username):
    if current_user.username == username:
        user = User.query.filter_by(username=username).first_or_404()
        messages = Message.query.filter_by(sender=user).order_by(Message.creation_date.desc())
        lst_id = return_list_messages_id(messages)
        return lst_id
    else:
        return "You can't enter to other user's messages"




