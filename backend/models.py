from datetime import date
from main import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    council = db.Column(db.String(64), index=True)  # ifc, phc, etc.
    # phi kappa psi, delta gamma, etc
    organization = db.Column(db.String(64), index=True)
    username = db.Column(db.String(64), index=True, unique=True)
    first_name = db.Column(db.String(64), index=True)
    last_name = db.Column(db.String(64), index=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    covid_tests = db.relationship('CovidTest', backref='user', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.username)


class CovidTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scheduled_date = db.Column(db.Date, index=True)
    result = db.Column(db.String(64), index=True,
                       default="Result Not Received")
    userid = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Test on {} came back: {}'.format(self.scheduled_date, self.result)
