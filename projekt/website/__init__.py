from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
DB_NAME = "database.db"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dobby'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    from .models import User,Note,PublicNote
    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    create_database(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    csrf = CSRFProtect(app)
    csrf.init_app(app)


    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))


    @app.after_request
    def add_security_headers(resp):
        resp.headers['Content-Security-Policy'] = "default-src *; style-src 'self' 'unsafe-inline' https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/ https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/; font-src 'self'  data:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://maxcdn.bootstrapcdn.com/bootstrap/ https://cdnjs.cloudflare.com/ajax/libs/popper.js/ https://code.jquery.com/"
        resp.headers['Server'] = "Secret"
        return resp

    return app

def create_database(app):
    if not path.exists('website/' + DB_NAME):
        with app.app_context():
            db.create_all()
        print('Database created')

