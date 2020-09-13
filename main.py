
# I was having some issues with circular imports as well as finding consistent answers
# regarding the deployment of more complex flask apps on Google App Engine, so I am currently
# developing this project in a single file in order to get it up and running as quickly as possible.
# I intend to explore the file structure more in the future and hopefully get it working then.


from flask import Flask, render_template, url_for, request, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse

""" -------------------- Declare the Config object (config.py) -------------------- """

import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'jfH78-68fGHPohka!lhaouHKL'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

""" -------------------- Initialize the application (main.py) -------------------- """

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'

""" -------------------- Declare the models to be used (models.py) -------------------- """

from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from hashlib import md5

class User(UserMixin, db.Model):
    """ Class representing a User """
    id = db.Column(db.Integer, primary_key=True)
    council = db.Column(db.String(64), index=True)  # ifc, phc, etc.
    organization = db.Column(db.String(64), index=True) # phi kappa psi, delta gamma, etc
    username = db.Column(db.String(64), index=True, unique=True)
    first_name = db.Column(db.String(64), index=True)
    last_name = db.Column(db.String(64), index=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    covid_tests = db.relationship('CovidTest', backref='user', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        """ Function that sets the password_hash variable equal to the hash of the inputted password """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """ Function that checks if the hash of the inputted password matches the stored password hash """
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(digest, size)


class CovidTest(db.Model):
    """ Class representing a COVID test """
    id = db.Column(db.Integer, primary_key=True)
    scheduled_date = db.Column(db.Date, index=True)
    result = db.Column(db.String(64), index=True,
                       default="Result Not Received")
    userid = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Test on {} came back: {}'.format(self.scheduled_date, self.result)

@login.user_loader
def load_user(id):
    """ User loader function that tells flask-login how to load a user"""
    return User.query.get(int(id))

""" --------------------------- Forms (forms.py) -------------------------- """

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo

class LoginForm(FlaskForm):
    """ Form to be used to return users to the login page """
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    repeat_password = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('This username already exists. Please select a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('This email is already in use. Please select a different email.')

class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    submit = SubmitField('Save Changes')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None and user.id != current_user.id:
            raise ValidationError('This username already exists. Please select a different username.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None and user.id != current_user.id:
            raise ValidationError('This email is already in use. Please select a different email.')

""" --------------------------- Routes (main.py or routes.py) -------------------------- """

@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template('index.html', title='Home')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page) != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Log In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, first_name=form.first_name.data, last_name=form.last_name.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you have been successfully registered into the system!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/reportTest')
@login_required
def reportTest():
    return render_template('reportTest.html', title='Report a Test')

@app.route('/resources')
@login_required
def resources():
    return render_template('resources.html', title='Resources')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        print("validate on submit")
        user = User.query.filter_by(id=current_user.id).first()
        print(user)
        user.username = form.username.data
        user.email = form.email.data
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        db.session.commit()
        flash('Your profile has been updated.')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        print("just a GET request")
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
    return render_template('profile.html', title='My Profile', form=form)



""" ------------------------- Run App Locally ------------------------- """

if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    # Flask's development server will automatically serve static files in
    # the "static" directory. See:
    # http://flask.pocoo.org/docs/1.0/quickstart/#static-files. Once deployed,
    # App Engine itself will serve those files as configured in app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)