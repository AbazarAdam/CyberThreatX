"""
User Authentication Module for CyberThreatX
Handles login, logout, and user session management.
"""

from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask import redirect, url_for, flash
import db

# Initialize Login Manager
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

class User(UserMixin):
    """User class for Flask-Login integration."""
    def __init__(self, user_dict):
        """Initializes a User object from a database row.

        Args:
            user_dict: Dictionary containing user ID, username, and role.
        """
        self.id = user_dict['id']
        self.username = user_dict['username']
        self.role = user_dict['role']

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID."""
    user_dict = db.get_user_by_id(int(user_id))
    if user_dict:
        return User(user_dict)
    return None

def init_auth(app):
    """Initializes authentication for the Flask app.

    Args:
        app: The Flask application instance.
    """
    login_manager.init_app(app)
    
    # Create default admin user if no users exist
    try:
        # Check if users table is empty or doesn't have admin
        import config
        admin = db.get_user_by_username(config.ADMIN_DEFAULT_USER)
        if not admin:
            db.create_user(
                config.ADMIN_DEFAULT_USER, 
                config.ADMIN_DEFAULT_PASS, 
                'admin'
            )
            import logging
            logger = logging.getLogger(__name__)
            logger.info(f"[*] Created default admin user: {config.ADMIN_DEFAULT_USER}")
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"[!] Warning: Could not create default admin: {e}")

def login_required_role(role):
    """Decorator for requiring a specific role."""
    from functools import wraps
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role != role and current_user.role != 'admin':
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
