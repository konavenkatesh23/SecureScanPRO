from flask import Flask
from config import SECRET_KEY

# Import Blueprints
from routes.auth_routes import auth_bp, bcrypt
from routes.dashboard_routes import dashboard_bp
from routes.scan_routes import scan_bp
from routes.report_routes import report_bp

# Testing Blueprints
from routes.test_routes import test_bp
from routes.test_xss_routes import xss_test_bp

app = Flask(__name__)

# Secret Key
app.secret_key = SECRET_KEY

# Initialize Flask-Bcrypt
bcrypt.init_app(app)

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(scan_bp)
app.register_blueprint(report_bp)

# Register Testing Blueprints
app.register_blueprint(test_bp)
app.register_blueprint(xss_test_bp)

if __name__ == "__main__":
    app.run(debug=True)