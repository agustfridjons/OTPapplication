from flask import Flask, render_template, url_for, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import re

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SECRET_KEY'] = 'SmbmKLg9sXLBz5Z8j2KXtA'

DATABASE = SQLAlchemy(app)

class User(DATABASE.Model):
    id = DATABASE.Column(DATABASE.Integer, primary_key=True)
    username = DATABASE.Column(DATABASE.String(50), nullable=False)
    email = DATABASE.Column(DATABASE.String(50), nullable=False)
    password = DATABASE.Column(DATABASE.String(50), nullable=False)
    date_created = DATABASE.Column(DATABASE.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<User %r' % self.username


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['POST', 'GET'])
def signUp():
    pas_regex = "^.*(?=.{8,})(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&+]).*$"
    invalid_input = "[\\t\\r\\n]|(--[^\\r\\n]*)|(\\/\\*[\\w\\W]*?(?=\\*)\\*\\/)"
    db=DATABASE
    if request.method == 'POST':
        form_content = [request.form['username'], request.form['email'], request.form['password'], request.form['cpassword']]
        for i in range(len(form_content)):
            if not re.match(invalid_input, form_content[i]):
                print("invalid input")
        account = User.query.filter_by(username=form_content[0]).first()
        user_exists = account != None
        print("Validating User")
        if form_content[0] == '':
            return redirect("/signup/error/0")
        if user_exists:
            return redirect("/signup/error/1")
        if not re.match(pas_regex, form_content[2]):
            return redirect("/signup/error/2")
        if not (form_content[2] == form_content[3]):
            return redirect("/signup/error/3")
        print("Making user")
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
        req = request.form
        username = req.get("username")
        password = req.get("password")
        account = User.query.filter_by(username=username).first()
        user_exists = account != None
        if user_exists:
            #OPT toodoo
            if account.password == password:
                session['username'] = account.username
                return redirect(url_for('index'))
            else:
                return "Invalid username or password"
        else:
            return "Invalid username or password"
    else:
        return render_template('signin.html')


@app.route('/signup/error/<id>')
def signup_error(id):
    if id == '0':
        message = 'Username cannot be empty'
    if id == '1':
        message = 'User already exists'
    if id == '2':
        message = 'Password doesn\'t fulfill requirements'
    if id == '3':
        message = 'Passwords have to match'
    return render_template('signup.html', message=message)


@app.route('/signout')
def signOut():
    session.pop('username', None)
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
