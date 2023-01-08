import datetime
from flask import Blueprint,redirect,url_for, render_template, request, flash
from .models import User
from flask import Flask
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import bleach
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
limiter = Limiter(app = Flask(__name__),key_func=get_remote_address)

auth = Blueprint('auth',  __name__)


@auth.route('/login', methods=['GET', 'POST'])
@limiter.limit("10/minute")
def login():
    if request.method == 'POST':
        nickname = bleach.clean(request.form.get('nickname'))
        password = bleach.clean(request.form.get('password'))

        user = User.query.filter_by(nickname=nickname).first()

        if user:
            if(db.session.query(User.attempts).filter_by(nickname = nickname).first().attempts != 0):
                if check_password_hash(user.password, password):
                    flash('Logowanie udane!', category='success')
                    setattr(User.query.filter_by(nickname=nickname).first(), 'attempts', 10)
                    setattr(User.query.filter_by(nickname=nickname).first(), 'lastLogin', datetime.datetime.now())
                    db.session.commit()
                    login_user(user, remember=True)
                    return redirect(url_for('views.home'))
                else:
                    db.session.query(User). \
                        filter(User.nickname == nickname). \
                        update({'attempts': User.attempts - 1})
                    if (db.session.query(User.attempts).filter_by(nickname=nickname).first().attempts == 0):
                        setattr(User.query.filter_by(nickname=nickname).first(), 'lastLogin', datetime.datetime.now())
                    db.session.commit()
                    flash('Nieprawidłowe hasło', category='error')
            else:
                print(datetime.datetime.now() - User.query.filter_by(nickname=nickname).first().lastLogin)
                if(datetime.datetime.now() - User.query.filter_by(nickname=nickname).first().lastLogin > datetime.timedelta(seconds=900)):
                    setattr(User.query.filter_by(nickname=nickname).first(), 'attempts', 10)
                    db.session.commit()
                    flash('Logowanie zostało odblokowane, spróbuj ponownie', category='success')
                else:
                    flash('Logowanie zostało zablokowane, wróć za jakiś czas', category='error')


        else:
            flash('Użytkownik z tą nazwą nie istnieje.', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign_up', methods=['GET', 'POST'])

def sign_up():
    if request.method == 'POST':
        email = bleach.clean(request.form.get('email'))
        nickname = bleach.clean(request.form.get('nickname'))
        password = bleach.clean(request.form.get('password'))
        user = User.query.filter_by(nickname=nickname).first()

        if(len(email) == 0  or len(nickname) == 0):
            flash('Pole email oraz nickname nie mogą być puste', category='error')
        elif user:
            flash('Podana nazwa użytownika jest zajęta', category='error')
        elif(len(password) < 8):
            flash('Hasło nie może być krótsze niż 8 znaków', category='error')
        elif(re.search(r"\d", password) is None):
            flash('Hasło musi zawierać przynajmniej 1 liczbę', category='error')
        elif (re.search(r"[A-Z]", password) is None):
            flash('Hasło musi zawierać przynajmniej 1 dużą litere', category='error')
        elif (re.search(r"[a-z]", password) is None):
            flash('Hasło musi zawierać przynajmniej 1 małą litere', category='error')
        elif (re.search(r"\W", password) is None):
            flash('Hasło musi zawierać przynajmniej 1 symbol specjalny', category='error')
        else:
            new_user = User(email=email, nickname=nickname, password=generate_password_hash(
                password, method='sha256', salt_length=16))
            db.session.add(new_user)
            db.session.commit()
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)

@auth.errorhandler(429)
def ratelimit_handler(e):
  return "Przekroczyłeś limit logowań, wróć za chwilę aby spróbować ponownie"