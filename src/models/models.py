import os
from src import db, login_manager, app
from flask_login import LoginManager, current_user, login_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import requests






class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(120))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def send_password_reset_email(self, token):
        apikey = os.getenv('API_KEY')
        sandbox = os.getenv('SANDBOX')
        url ='https://api.mailgun.net/v3/{0}/messages'.format(sandbox)
        return requests.post(url,
                auth=("api",apikey),
                data={"from": "Cool App <mailgun@{0}>".format(sandbox),
                "to": [self.email],
                "subject": "Reset pasword",
                "text": f"Go to http://localhost:5000/auth/new_password/{token}."})

    def __ref__(self):
        return '<User %r>' %self.username
    
   

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


