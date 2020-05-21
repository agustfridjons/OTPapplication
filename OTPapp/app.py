import base64
import random
import string
from datetime import datetime
from flask import Flask, render_template, url_for, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import re

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SECRET_KEY'] = 'SmbmKLg9sXLBz5Z8j2KXtA'
app.config.from_pyfile('config.cfg')

URLSS = URLSafeTimedSerializer(app.config['SECRET_KEY'])

mail = Mail(app)

db = SQLAlchemy(app)

# Creating database table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    email_confirmed = db.Column(db.Boolean, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return '<User %r' % self.username


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST', 'GET'])
def signUp():
    database = db

    if request.method == 'POST':
        # Defining regular expression strings
        pas_regex = '^.*(?=.{8,})(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&+]).*$'
        email_regex = '\w+[.|\w]\w+@\w+[.]\w+[.|\w+]\w+'

        # receiving  content from form
        form_content = [request.form['username'], request.form['email'], request.form['password'], request.form['cpassword']]
        account = User.query.filter_by(username=form_content[0]).first()
        account_email = User.query.filter_by(email=form_content[1]).first()
        user_exists = account != None
        email_exists = account_email != None
        print("Validating User")
        # If statements checking for valid sign in
        for i in form_content:
            if i == '':                   # Checking if fields are empty
                return redirect("/signup/error/0")
        if user_exists:                                 # Checking if user already exists
            return redirect("/signup/error/1")
        if (not re.match(email_regex, form_content[1])) | email_exists:  # Checking if email follows the right format
            return redirect("/signup/error/4")
        if not re.match(pas_regex, form_content[2]):    # Checking if password follows the right format
            return redirect("/signup/error/2")
        if not (form_content[2] == form_content[3]):    # Checking if 'password' and 'confirmed password' match
            return redirect("/signup/error/3")


        print("Making user")
        # Adds the new user to the DB
        new_user = User(username=form_content[0], email=form_content[1], password=form_content[2], email_confirmed=False)
        print("Sending confirm email")
        sendConfirmationEmail(form_content[1])
        try:
            print("Adding to db")
            database.session.add(new_user)
            database.session.commit()
            print("User added")
            return redirect(url_for('index'))
        except:
            return 'Error adding user'
    else:
        return render_template('signup.html', message="")


@app.route('/signin', methods=['GET', 'POST'])
def signIn():
    if request.method == 'POST':
        # Fetching input fields from form
        req = request.form
        username = req.get("username")
        password = req.get("password")
        account = User.query.filter_by(username=username).first()
        user_exists = account != None

        if password == None:
            return redirect(url_for('signIn'))

        # If username exists and password is right send OTP
        if user_exists & (account.password == password):
            if account.email_confirmed: #TODO email OPT
                sendOTP(account.email)
                return redirect('/confirm/'+ account.username)
            else:
                return 'Invalid username or password, <a href="/expired"> email might not have been confirmed</a>'
        else:
            return 'Invalid username or password, <a href="/expired"> email might not have been confirmed</a>'
    else:
        return render_template('signin.html')


# Handling Error messages
@app.route('/signup/error/<id>')
def signup_error(id):
    if id == '0':
        message = 'Fields cannot be empty'
    if id == '1':
        message = 'Invalid username'
    if id == '4':
        message = 'Invalid email address'
    if id == '2':
        message = 'Password doesn\'t fulfill requirements'
    if id == '3':
        message = 'Passwords have to match'
    return render_template('signup.html', message=message)


# Takes User out of session
@app.route('/signout')
def signOut():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/confirm/<username>', methods=['POST', 'GET'])
def confirmOTP(username):
    if request.method == 'POST':
        timer = (datetime.now() - session['OTPTimer']).seconds
        if timer < 1800:
            if hashOTP(request.form['OTP']) == session['OTP']:
                session['username'] = username
                session.pop('OTP', None)
                session.pop('OTPTimer', None)
                return redirect(url_for('index'))
            else:
                msg = 'Wrong password'
                return render_template('confirmation.html', message=msg, user=username)
        else:
            account = User.query.filter_by(username=username).first()
            sendOTP(account.email)
            return render_template('confirmation.html', message='Password expired, we sent a new one check your mail', user=username)
    else:
        print(username)
        return render_template('confirmation.html', message='', user=username)


@app.route('/expired', methods=['POST', 'GET'])
def emailExpired():
    if request.method == 'POST':
        email = request.form['email']
        account = User.query.filter_by(email=email).first()
        user_exists = account != None
        if user_exists:
            sendConfirmationEmail(email)
            return render_template('expired.html', message="Email sent!")
    else:
        return render_template('expired.html', message="")


#User has an hour to respond
@app.route('/confirm_email/<token>')
def confirmEmail(token):
    try:
        email = URLSS.loads(token, salt='rMb2LL4smLvY5Z8x2KSbP', max_age=3600)
    except SignatureExpired:
        return render_template('expired.html', message="")
    account = User.query.filter_by(email=email).first()
    user_exists = account != None
    if user_exists:
        account.email_confirmed = True
        db.session.commit()
        return render_template('confirmemail.html')
    else:
        return render_template('expired.html', message="Error confirming email")


def sendConfirmationEmail(email):
    token = URLSS.dumps(email, salt='rMb2LL4smLvY5Z8x2KSbP')
    msg = Message('Confirm Email', recipients=[email])
    link = url_for('confirmEmail', token=token, _external=True)
    msg.body = 'Your confirmation link is {}'.format(link)
    mail.send(msg)


def sendOTP(email):
    msg = Message('Safespace One Time Password', recipients=[email])
    OTP = generateOTP()
    session['OTP'] = hashOTP(OTP)
    session['OTPTimer'] = datetime.now()
    msg.body = 'Your one time password is: ' + OTP + ' use it to login to safespace.'
    mail.send(msg)


def hashOTP(OTP):
    hashString = ''.join(OTP + 'rMb2LL4smLvY5Z8x2KSbP')
    return base64.standard_b64encode(hashString.encode('utf-8')).decode('utf-8')


def generateOTP():
    lettersAndDigits = string.ascii_uppercase + string.digits
    return ''.join((random.choice(lettersAndDigits) for i in range(8)))


if __name__ == '__main__':
    app.run(debug=True)
