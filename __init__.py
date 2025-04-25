from flask import Flask
from app.database import DatabaseConnection
import os
from flask_session import Session
import logging
from flask_login import LoginManager, UserMixin
from flask_mail import Mail


# ✅ Initialize Database Connection
db = DatabaseConnection()

# ✅ Initialize Flask-Login
login_manager = LoginManager()
# — initialize the Mail extension
mail = Mail()

# Add User class here
class User(UserMixin):
    def __init__(self, id, username, email, dob=None, phone_number=None, gender=None):
        self.id = id
        self.username = username
        self.email = email
        self.dob = dob
        self.phone_number = phone_number
        self.gender = gender


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login with additional profile fields"""
    user_data = db.fetch_one("SELECT id, username, email, dob, phone_number, gender FROM users WHERE id = %s", (user_id,))
    
    if user_data:
        return User(
            user_data['id'], 
            user_data['username'], 
            user_data['email'], 
            user_data.get('dob'), 
            user_data.get('phone_number'), 
            user_data.get('gender')
        )
    return None


def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__, 
                static_folder='static', 
                template_folder='templates')
    
    # ✅ Set Secret Key
    app.secret_key = os.urandom(24)
    app.config.update(
        MAIL_SERVER      = 'smtp.gmail.com',
        MAIL_PORT        = 587,
        MAIL_USE_TLS     = True,
        MAIL_USERNAME    = 'your email',
        MAIL_PASSWORD    = 'your app password',
        MAIL_DEFAULT_SENDER = ('Fashion Store','your email')
    )
    mail.init_app(app)

    # ✅ Configure Flask-Login
    login_manager.init_app(app)
    login_manager.login_view = 'login'  # Redirects to login page if not authenticated

    # ✅ Configure Flask Session
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = './.flask_session/'
    
    # Ensure session directory exists
    os.makedirs('./.flask_session/', exist_ok=True)
    
    Session(app)

    # ✅ Configure Logging
    logging.basicConfig(level=logging.DEBUG)
    
    # ✅ Import routes inside create_app() to avoid circular imports
    from app import routes
    routes.init_routes(app)
    

    return app
