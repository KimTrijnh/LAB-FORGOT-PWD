import os
from src import ts, db
from flask import Blueprint, redirect, render_template, url_for, flash, request
from .forms import LoginForm, EmailForm, PasswordForm
from src.models.models import User
from werkzeug.security import generate_password_hash, check_password_hash


auth_blueprint = Blueprint('auth', __name__, template_folder='templates/auth')

@auth_blueprint.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            return redirect(url_for('index'))
        else:
            flash('wrong username/password')
    return render_template('auth/login.html', title='Sign In', form=form)


@auth_blueprint.route('/reset', methods=["GET", "POST"])
def reset():
    form = EmailForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = ts.dumps(user.email, salt='recover-password-secret')
            user.send_password_reset_email(token)
            flash('password reset email sent')
            return redirect(url_for('auth.login'))
        # Redirect to the main login form here with a "password reset email sent!"
        else:
            flash('invalid email, please enter again')
    return render_template('auth/reset.html', form=form)

@auth_blueprint.route('/new_password/<token>', methods=['GET', 'POST'])
def create_new_password(token):
    form = PasswordForm()
    try:
        email = ts.loads(token, salt='recover-password-secret', max_age=3600)
        if form.validate_on_submit():
            user = User.query.filter_by(email=email).first()
            user.password_hash = generate_password_hash(form.password.data)
            db.session.commit()
            flash('password changed')
            return redirect(url_for('auth.login'))
    except:
        flash('The password reset link is invalid or has expired.', 'error')
    
    print(form.errors)
    return render_template('/auth/create_new_password.html', form = form)
