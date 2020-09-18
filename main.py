
# I was having some issues with circular imports as well as finding consistent answers
# regarding the deployment of more complex flask apps on Google App Engine, so I am currently
# developing this project in a single file in order to get it up and running as quickly as possible.
# I intend to explore the file structure more in the future and hopefully get it working then.


from flask import Flask, render_template, url_for, request, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from sqlalchemy_utils.types.encrypted.encrypted_type import EncryptedType

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
    organization = db.Column(db.String(64), index=True) # phi kappa psi, delta gamma, etc
    is_admin = db.Column(db.Boolean, index=True, default=False) # boolean representing whether they're an admin
    username = db.Column(db.String(64), index=True, unique=True)
    first_name = db.Column(db.String(64), index=True)
    last_name = db.Column(db.String(64), index=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128)) 
    is_verified = db.Column(db.Boolean()) # plan to delete this when I switch to Postgres
    covid_tests = db.relationship('CovidTest', backref='user', lazy='dynamic') # declares a one to many relationship between users and covid tests

    def __repr__(self):
        """ Function to define string representation of class """
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        """ Function that sets the password_hash variable equal to the hash of the inputted password.
            Call this function to set the password for a user """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """ Function that checks if the hash of the inputted password matches the stored password hash.
            Returns true if the password hashes match """
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        """ Returns the url for the users avatar (uses Gravatar) """
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(digest, size)


class CovidTest(db.Model):
    """ Class representing a COVID test """
    id = db.Column(db.Integer, primary_key=True)
    scheduled_date = db.Column(db.Date, index=True) # date the test was scheduled for
    result = db.Column(db.String(64), index=True, default="Result Not Received") # results of test
    userid = db.Column(db.Integer, db.ForeignKey('user.id')) # id of the user that the test was for

    def __repr__(self):
        """ String representation of the CovidTest class """
        return '<Test on {} came back: {}>'.format(self.scheduled_date, self.result)

@login.user_loader
def load_user(id):
    """ User loader function that tells flask-login how to load a user """
    return User.query.get(int(id))

""" --------------------------- Forms (forms.py) -------------------------- """

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, DateField, RadioField, SelectField, TextAreaField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo

class LoginForm(FlaskForm):
    """ Form to be used for users to login """
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    """ Form to be used for users to register """
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    # repeat password option, standard procedure for registering
    repeat_password = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        """ Function that ensures the username is unique """
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('This username already exists. Please select a different username.')

    def validate_email(self, email):
        """ Function that ensures the email address is unique """
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('This email is already in use. Please select a different email.')

class EditProfileForm(FlaskForm):
    """ Form to be used for users to edit their profiles """
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    submit = SubmitField('Save Changes')

    def validate_username(self, username):
        """ Function that ensures the username is unique (unless it hasn't been altered) """
        user = User.query.filter_by(username=username.data).first()
        if user is not None and user.id != current_user.id:
            raise ValidationError('This username already exists. Please select a different username.')
    
    def validate_email(self, email):
        """ Function that ensures the email is unique (unless it hasn't been altered) """
        user = User.query.filter_by(email=email.data).first()
        if user is not None and user.id != current_user.id:
            raise ValidationError('This email is already in use. Please select a different email.')

class ReportTestingScheduleForm(FlaskForm):
    """ Form to report a scheduled test """
    scheduled_date = StringField('Date', validators=[DataRequired()])
    submit = SubmitField('Report Scheduled Test')

    def validate_scheduled_date(self, scheduled_date):
        """ Ensures that the input was a valid date """
        # get the date data
        date_string = scheduled_date.data
        # ensure it's the correct length and has /'s in the correct locations
        if len(date_string) != 10 or date_string[2] != '/' or date_string[5] != '/':
            raise ValidationError('Please enter a valid date of the following format: MM/DD/YYYY')
        # split the day month and year
        date_list = date_string.split("/")
        # make sure there were only two /'s
        if len(date_list) != 3:
            raise ValidationError('Please enter a valid date of the following format: MM/DD/YYYY')
        day = int(date_list[1])
        month = int(date_list[0])
        year = int(date_list[2])
        # try creating a date object from this data
        try:
            # if valid, proceed
            actual_date = date(year, month, day)
        except ValueError:
            #throw an error if not valid
            raise ValidationError('Please enter a valid date')
        #make sure the year is equal to the current year
        if year != datetime.now().year:
            raise ValidationError('Please be sure to only report tests for the current year.')

    
class ReportTestingResultsForm(FlaskForm):
    """ Form for reporting the results of a test """
    scheduled_dates = SelectField('Results for Test on:', validators=[DataRequired()])
    results = RadioField('Results', validators=[DataRequired()], choices=[('Positive','Positive'), ('Negative/Not Detected', 'Negative/Not Detected'), ('Inconclusive', 'Inconclusive')])
    submit = SubmitField('Report Test Results')

class DeleteUserAccountForm(FlaskForm):
    """ Form to delete the account for a user """
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Permanently Delete User')

class EmailUserForm(FlaskForm):
    """ Form for an admin to send an email to a user account """
    email = StringField('To', validators=[DataRequired()])
    subject = StringField('Subject')
    body = TextAreaField('Body')
    submit = SubmitField('Send Email')

""" --------------------------- Routes (main.py or routes.py) -------------------------- """

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    """ Route to the home page, also logic for reporting scheduled tests and test results """
    # populate the user info and org info dictionaries using data from the server
    user_info = populate_user_info()
    organization_info = populate_organization_info()
    # declare the possible forms to be used in the page
    sched_form = ReportTestingScheduleForm()
    result_form = ReportTestingResultsForm()
    # declare the choices for the select list for scheduled tests to be dates of tests that the user hasn't reported results for
    result_form.scheduled_dates.choices = [(t.id, t.scheduled_date) for t in user_info["scheduled_tests"] if t.result == "Result Not Received"]
    # if the user reports a scheduled test...
    if sched_form.validate_on_submit():
        # format the date appropriately
        d_list = sched_form.scheduled_date.data.split("/")
        d_date = date(int(d_list[2]), int(d_list[0]), int(d_list[1]))
        # create a CovidTest instance using this date
        test = CovidTest(scheduled_date=d_date, userid=current_user.id)
        # add this instance to the database
        db.session.add(test)
        db.session.commit()
        # flash confirmation and reload home page
        flash('Thank you for registering your test on ' + sched_form.scheduled_date.data)
        return redirect(url_for('index'))
    elif result_form.validate_on_submit():
        # get the selected covid test
        covid_test = CovidTest.query.filter_by(id=result_form.scheduled_dates.data).first()
        # get the reported result and add it to the covid test
        covid_test.result = result_form.results.data
        # update this covid test in the database
        db.session.commit()
        # flash confirmation and reload home page
        flash("Thank you for reporting your test results from " + covid_test.scheduled_date.strftime("%m/%d/%Y"))
        return redirect(url_for('index'))
    # not a form submit? just render the template with the necessary variables
    return render_template('index.html', title='Home', sched_form=sched_form, result_form=result_form, user_info=user_info, organization_info=organization_info)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Route to the login page, also logic for logging in """
    # send to home page if user is logged in
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    # instantiate the login form
    form = LoginForm()
    # if the form is submitted...
    if form.validate_on_submit():
        # get the appropriate user
        user = User.query.filter_by(username=form.username.data).first()
        # if a user with this username does not exist or the password is incorrect, reload login page
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        # if valid credentials, log the user in
        login_user(user, remember=form.remember_me.data)
        # load the path to the next page
        next_page = request.args.get('next')
        # send to home page if any issues with the next_page variable
        if not next_page or url_parse(next_page) != '':
            next_page = url_for('index')
        # send to the next page
        return redirect(next_page)
    # not a form submit? just render the template with the necessary variables
    return render_template('login.html', title='Log In', form=form)

@app.route('/logout')
def logout():
    """ route to logout a user """
    # log the user out
    logout_user()
    # send them home (will redirect to login page)
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """ route to register page, also includes logic to register a user """
    # if user is logged in, send them to the home page
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    # instantiate the registration form
    form = RegistrationForm()
    # if the form is submitted...
    if form.validate_on_submit():
        # hardcoded for my own organization
        organization = "Phi Kappa Psi"
        # create a user with the inputted data
        user = User(username=form.username.data, email=form.email.data, first_name=form.first_name.data, last_name=form.last_name.data, organization=organization)
        # set the password for this account
        user.set_password(form.password.data)
        # add this user to the database
        db.session.add(user)
        db.session.commit()
        # flash success message, login the user, and send them to the home pages
        flash('Congratulations, you have been successfully registered into the system!')
        login_user(user)
        return redirect(url_for('index'))
    # not a form submit? just render the template with the necessary variables
    return render_template('register.html', title='Register', form=form)

@app.route('/resources')
@login_required
def resources():
    """ route to the resources page """
    return render_template('resources.html', title='Resources')

@app.route('/help')
@login_required
def help():
    """ route to the help page """
    return render_template('help.html', title='Help')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    """ route to the admin page, include logic to delete user accounts """
    # instantiate the necessary forms
    delete_form = DeleteUserAccountForm()
    email_form = EmailUserForm()
    # get a list of the admins and general members for the current user's organization
    admins = User.query.filter(User.is_admin==1,User.organization==current_user.organization).all()
    members = User.query.filter(User.is_admin==0,User.organization==current_user.organization).all()
    # only show this page and accept post requests if the user is an admin
    if current_user.is_admin:
        # if the delete form is submitted...
        if delete_form.validate_on_submit:
            print("Delete User")
        elif email_form.validate_on_submit(): # if the email form is submitted...
            print("Email User")
        return render_template('admin.html', title='Manage Organization', delete_form=delete_form, email_form=email_form, admins=admins, members=members)
    else:
        # if user is not an admin, flash error and redirect them to the home page
        flash("You must be an administrator for your organization to view this page.")
        return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """ route to the profile page, includes logic to edit profile """
    # instantiate the edit profile form
    form = EditProfileForm()
    # if the form is submitted
    if form.validate_on_submit():
        # get the current user
        user = User.query.filter_by(id=current_user.id).first()
        # set the user info to match the data from the form
        user.username = form.username.data
        user.email = form.email.data
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        # update this record in the database
        db.session.commit()
        # flash success message and reload page
        flash('Your profile has been updated.')
        return redirect(url_for('profile'))
    elif request.method == 'GET': # else if its a get request...
        # populate form with current user data
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
    # render the page with the appropriate variables
    return render_template('profile.html', title='My Profile', form=form)


""" ------------------------- Helper Functions ------------------------- """

def populate_user_info():
    """ Helper function that populates and returns a dictionary with the appropriate user information """
    # get a list of all of the scheduled tests for this given user
    scheduled_tests = CovidTest.query.filter_by(userid=current_user.id).order_by(CovidTest.scheduled_date.asc()).all()
    total_scheduled = len(scheduled_tests)
    # get a list of all scheduled tests in the future (date is today or later)
    upcoming_tests = CovidTest.query.filter(CovidTest.userid==current_user.id, CovidTest.scheduled_date >= datetime.now().date()).order_by(CovidTest.scheduled_date.asc()).all()
    # get the number of positive, negative, inconclusive, and not reported tests & their relative percentages for this user
    if (total_scheduled > 0):
        # get counts and percentages of each test result
        # positive tests
        positive_count = CovidTest.query.filter(CovidTest.userid==current_user.id, CovidTest.result=="Positive").count()
        positive_percentage = str(100*positive_count / total_scheduled) + "%"
        # negative/not detected tests
        negative_count = CovidTest.query.filter(CovidTest.userid==current_user.id, CovidTest.result=="Negative/Not Detected").count()
        negative_percentage = str(100*negative_count / total_scheduled) + "%"
        # inconclusive tests
        inconclusive_count = CovidTest.query.filter(CovidTest.userid==current_user.id, CovidTest.result=="Inconclusive").count()
        inconclusive_percentage = str(100*inconclusive_count / total_scheduled) + "%"
        # unreported tests
        unreported_count = CovidTest.query.filter(CovidTest.userid==current_user.id, CovidTest.result=="Result Not Received").count()
        unreported_percentage = str(100*unreported_count / total_scheduled) + "%"
    else: # if no tests, set all to 0 (separate statement to avoid divide by 0 error)
        positive_count = 0
        positive_percentage = "0%"
        negative_count = 0
        negative_percentage = "0%"
        inconclusive_count = 0
        inconclusive_percentage = "0%"
        unreported_count = 0
        unreported_percentage = "0%"
    # declare user_info dictionary to store all user data we wish to display on the page
    user_info = {"scheduled_tests": scheduled_tests, "total_scheduled": total_scheduled, "upcoming_tests": upcoming_tests, "positive_count": positive_count, "positive_percentage": positive_percentage, "negative_count": negative_count, "negative_percentage": negative_percentage, "inconclusive_count": inconclusive_count, "inconclusive_percentage": inconclusive_percentage, "unreported_count": unreported_count, "unreported_percentage": unreported_percentage}
    return user_info

def populate_organization_info():
    """ Helper function that populates and returns a dictionary with the appropriate organization information """
    # get a list of all scheduled tests for this organization
    scheduled_tests = CovidTest.query.join(User, CovidTest.userid==User.id).filter(User.organization == current_user.organization).order_by(CovidTest.scheduled_date.asc()).all()
    # declare org_info dictionary to store all organization data we wish to display on the page
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