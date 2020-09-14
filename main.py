
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

from datetime import date, datetime
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
        return '<Test on {} came back: {}>'.format(self.scheduled_date, self.result)

@login.user_loader
def load_user(id):
    """ User loader function that tells flask-login how to load a user"""
    return User.query.get(int(id))

""" --------------------------- Forms (forms.py) -------------------------- """

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, DateField, RadioField, SelectField
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

class ReportTestingScheduleForm(FlaskForm):
    scheduled_date = StringField('Date', validators=[DataRequired()])
    submit = SubmitField('Report Scheduled Test')

    def validate_scheduled_date(self, scheduled_date):
        date_string = scheduled_date.data
        if len(date_string) != 10 or date_string[2] != '/' or date_string[5] != '/':
            raise ValidationError('Please enter a valid date of the following format: MM/DD/YYYY')
        date_list = date_string.split("/")
        if len(date_list) != 3:
            raise ValidationError('Please enter a valid date of the following format: MM/DD/YYYY')
        day = int(date_list[1])
        month = int(date_list[0])
        year = int(date_list[2])
        try:
            actual_date = date(year, month, day)
        except ValueError:
            raise ValidationError('Please enter a valid date')
        if year != datetime.now().year:
            raise ValidationError('Please be sure to only report tests for the current year.')

    
class ReportTestingResultsForm(FlaskForm):
    scheduled_dates = SelectField('Results for Test on:', validators=[DataRequired()])
    results = RadioField('Results', validators=[DataRequired()], choices=[('Positive','Positive'), ('Negative/Not Detected', 'Negative/Not Detected'), ('Inconclusive', 'Inconclusive')])
    submit = SubmitField('Report Test Results')

""" --------------------------- Routes (main.py or routes.py) -------------------------- """

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    user_info = populate_user_info()
    organization_info = populate_organization_info()
    #user_info = {"total_scheduled": 13, "positive_count": 8, "positive_percentage": "15%", "negative_count": 12, "negative_percentage": "60%", "unreported_count": 10, "unreported_percentage": "25%"}
    sched_form = ReportTestingScheduleForm()
    result_form = ReportTestingResultsForm()
    result_form.scheduled_dates.choices = [(t.id, t.scheduled_date) for t in user_info["scheduled_tests"] if t.result == "Result Not Received"]
    if sched_form.validate_on_submit():
        print("Schedule")
        d_list = sched_form.scheduled_date.data.split("/")
        d_date = date(int(d_list[2]), int(d_list[0]), int(d_list[1]))
        test = CovidTest(scheduled_date=d_date, userid=current_user.id)
        db.session.add(test)
        db.session.commit()
        flash('Thank you for registering your test on ' + sched_form.scheduled_date.data)
        return redirect(url_for('index'))
    elif result_form.validate_on_submit():
        print("Results")
        covid_test = CovidTest.query.filter_by(id=result_form.scheduled_dates.data).first()
        covid_test.result = result_form.results.data
        db.session.commit()
        flash("Thank you for reporting your test results from " + covid_test.scheduled_date.strftime("%m/%d/%Y"))
        return redirect(url_for('index'))
    return render_template('index.html', title='Home', sched_form=sched_form, result_form=result_form, user_info=user_info, organization_info=organization_info)

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
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you have been successfully registered into the system!')
        login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html', title='Register', form=form)

@app.route('/resources')
@login_required
def resources():
    return render_template('resources.html', title='Resources')

@app.route('/help')
@login_required
def help():
    return render_template('help.html', title='Help')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        user = User.query.filter_by(id=current_user.id).first()
        user.username = form.username.data
        user.email = form.email.data
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        db.session.commit()
        flash('Your profile has been updated.')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
    return render_template('profile.html', title='My Profile', form=form)


""" ------------------------- Helper Functions ------------------------- """

def populate_user_info():
    """ Helper function that populates and returns a dictionary with the appropriate user information """
    # get a list of all of the scheduled tests for this given user
    scheduled_tests = CovidTest.query.filter_by(userid=current_user.id).order_by(CovidTest.scheduled_date.asc()).all()
    # get a list of all scheduled tests in the future (date is today or later)
    upcoming_tests = CovidTest.query.filter(CovidTest.userid==current_user.id, CovidTest.scheduled_date >= datetime.now().date()).order_by(CovidTest.scheduled_date.asc()).all()
    print(upcoming_tests)
    #tests = [CovidTest(id=4,userid=2, result="Result Not Received", scheduled_date=date(2020, 9, 13)), CovidTest(id=5,userid=2, result="Result Not Received", scheduled_date=date(2020, 9, 15)), CovidTest(id=6,userid=2, result="Negative", scheduled_date=date(2020, 9, 14))]
    user_info = {"scheduled_tests": scheduled_tests, "total_scheduled": len(scheduled_tests), "upcoming_tests": upcoming_tests, "positive_count": 8, "positive_percentage": "15%", "negative_count": 12, "negative_percentage": "60%", "unreported_count": 10, "unreported_percentage": "25%"}
    return user_info

def populate_organization_info():
    """ Helper function that populates and returns a dictionary with the appropriate organization information """
    scheduled_tests = CovidTest.query.join(User, CovidTest.userid==User.id).filter(User.organization == current_user.organization).order_by(CovidTest.scheduled_date.asc()).all()
    org_info = {}
    return org_info


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