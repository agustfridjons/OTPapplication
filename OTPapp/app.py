from flask import Flask, render_template, url_for, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
import re

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SECRET_KEY'] = 'SmbmKLg9sXLBz5Z8j2KXtA'

DATABASE = SQLAlchemy(app)

# Creating database table
class User(DATABASE.Model):
    id = DATABASE.Column(DATABASE.Integer, primary_key=True)
    username = DATABASE.Column(DATABASE.String(50), nullable=False)
    email = DATABASE.Column(DATABASE.String(50), nullable=False)
    password = DATABASE.Column(DATABASE.String(50), nullable=False)

    def __repr__(self):
        return '<User %r' % self.username


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['POST', 'GET'])
def signUp():
    db=DATABASE

    if request.method == 'POST':
        # Defining regular expression strings
        pas_regex = '^.*(?=.{8,})(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&+]).*$'
        email_regex = '\w+[.|\w]\w+@\w+[.]\w+[.|\w+]\w+'

        # receiving  content from form
        form_content = [request.form['username'], request.form['email'], request.form['password'], request.form['cpassword']]
        account = User.query.filter_by(username=form_content[0]).first()
        user_exists = account != None
        print("Validating User")
        # If statements checking for valid sign in
        for i in form_content:
            if form_content[i] == '':                   # Checking if fields are empty
                return redirect("/signup/error/0")
        if user_exists:                                 # Checking if user already exists
            return redirect("/signup/error/1")
        if not re.match(email_regex, form_content[1]):  # Checking if eamil follows the right format
            return redirect("/signup/error/4")
        if not re.match(pas_regex, form_content[2]):    # Checking if password follows the right format
            return redirect("/signup/error/2")
        if not (form_content[2] == form_content[3]):    # Checking if 'password' and 'confirmed password' match
            return redirect("/signup/error/3")
        print("Making user")

        # Adds the new user to the DB
        new_user = User(username=form_content[0], email=form_content[1], password=form_content[2])
        try:
            print("Adding to db")
            db.session.add(new_user)
            db.session.commit()
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

        # If username exists and password is right send OTP
        if user_exists & account.password == password:
            if True: #TODO email OPT
                session['username'] = account.username
                return redirect(url_for('index'))
        else:
            return "Invalid username or password"
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


if __name__ == '__main__':
    app.run(debug=True)
