from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import logging
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'fbc626b2f5cf5c7de4d1ea21aef55440c154aabc3a741466bb81e5a0330c43e0'  # Necessary for using sessions securely

# Configure logging
logging.basicConfig(
    filename='security_events.log',  # Log file name
    level=logging.INFO,              # Log level
    format='%(asctime)s - %(levelname)s - %(message)s'  # Log format
)

# Create a logger object
logger = logging.getLogger()

# Log an event for successful login (security event example)
def log_success_event(user, event_description):
    logger.info(f"SUCCESS: User {user} - {event_description}")

# Log an event for failed login or any other failed security event
def log_failure_event(user, event_description):
    logger.warning(f"FAILURE: User {user} - {event_description}")


app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session expiration set to 30 minutes

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///firstapp.db"
with app.app_context():
    db = SQLAlchemy(app)

class Credentials(db.Model):
    sno = db.Column(db.Integer, primary_key = True, autoincrement = True)
    username = db.Column(db.String(100), nullable = False)
    password = db.Column(db.String(100), nullable = False)
    def __repr__(self):
        return f"{self.sno} : {self.username}"
    
class Comments(db.Model):
    comment_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), nullable = False)
    comment_text = db.Column(db.String(500), nullable=False)

def authentication(username, password):
    # Find user in the database
    user = Credentials.query.filter_by(username=username).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return 1
    return 0

#first login page
@app.route('/', methods = ['GET','POST'])
def login():
    if request.method=='POST':
        username = request.form['username']
        password = request.form['password']
        if authentication(username, password):
            session['user'] = username
            # Log the successful login event
            log_success_event(username, "Login successful")
            return redirect(url_for('display1'))
        # Log the failed login attempt
        log_failure_event(username, "Login failed due to incorrect credentials")
    return render_template('login.html')

#Second signup page page
@app.route('/signup', methods = ['GET','POST'])
def signup():
    if request.method=='POST':
        username = request.form['email']
        user = Credentials.query.filter_by(username=username).first()
        if user:
            return 'the email already exists'
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        if username and password:
            data = Credentials(username = username, password = hashed_password.decode('utf-8'))
            db.session.add(data)
            db.session.commit()
            log_success_event(username, "signup successful")
            return redirect(url_for('login'))  # Redirect to login after signup
    return render_template('signup.html')

#Third page to post comment after successful login
@app.route('/display1', methods = ['GET','POST'])
def display1():
    if not session.get('user'):  # Check if the user is logged in
        return redirect(url_for('login'))  # Redirect to login if not logged in
    username = session['user']  # Get the username from the session
    if request.method=='POST':
        comment_text = request.form['comment']
        # Find the user in the database
        user = Credentials.query.filter_by(username=username).first()
        if user:
             # Add the comment to the database
            new_comment = Comments(username = username, comment_text=comment_text)
            db.session.add(new_comment)
            db.session.commit()
            # After adding, re-query the comments to include the new comment
            return redirect(url_for('display1'))
    user_comments = Comments.query.all()
    return render_template('display1.html',comments=user_comments)

@app.route('/logout', methods=['POST'])
def logout():
    # Clear the session, effectively logging out the user
    username = session['user']  # Get the username from the session
    session.pop('user', None)  # Remove 'username' from session if it exists
    log_success_event(username, "Logged out successfully")
    return redirect(url_for('login'))  # Redirect to login page

if __name__ =="__main__":
    app.run(debug=True, port = 80)