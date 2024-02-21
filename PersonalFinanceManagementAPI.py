from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import bcrypt
import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_cors import CORS

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this in production
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)  # Shorter token expiration time
jwt = JWTManager(app)
api = Api(app)

# Set up rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per day", "10 per hour"]
)

# Dummy database for users and subscription plans
users = {
    "user1": {
        "password": bcrypt.hashpw('password'.encode('utf-8'), bcrypt.gensalt()),
        "email": "user1@example.com",
        "subscription_plan": "basic",
        "income": 5000,  # Example income in dollars
        "expenses": {
            "rent": 1500,
            "utilities": 300,
            "food": 500,
            "entertainment": 200
        },
        "goals": {
            "emergency_fund": 1000,
            "vacation": 2000,
            "retirement": 50000
        },
        "investments": {
            "stocks": 10000,
            "bonds": 5000
        }
    }
}

subscription_plans = {
    "basic": {"price": 19.99, "token_allocation": 5000},
    "pro": {"price": 49.99, "token_allocation": 20000},
    "enterprise": {"price": "custom", "token_allocation": "custom"}
}

# Email configuration
EMAIL_HOST = 'smtp.example.com'
EMAIL_PORT = 587
EMAIL_USERNAME = 'your_email@example.com'
EMAIL_PASSWORD = 'your_email_password'

# Enable CORS protection
CORS(app)

# Set up logging
logging.basicConfig(filename='api.log', level=logging.INFO)

# Send email function
def send_email(subject, recipient, body):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USERNAME
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        logging.info(f"Email sent to {recipient} successfully")
    except Exception as e:
        logging.error(f"Failed to send email to {recipient}: {str(e)}")

# Two-factor authentication endpoint
class TwoFactorAuth(Resource):
    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()
        token = str(random.randint(100000, 999999))  # Generate 6-digit random token
        users[current_user]['2fa_token'] = token
        send_email("Two-Factor Authentication Code", users[current_user]['email'], f"Your 2FA token is: {token}")
        return {"message": "Two-factor authentication code sent to your email"}, 200

# IP Whitelisting endpoint
class WhitelistIP(Resource):
    @jwt_required()
    def put(self):
        current_user = get_jwt_identity()
        users[current_user]['whitelisted_ip'] = request.remote_addr
        return {"message": "Your IP address has been whitelisted"}, 200

# Audit logging decorator
def log_action(action):
    def decorator(func):
        def wrapper(*args, **kwargs):
            logging.info(f"Action: {action} - User: {get_jwt_identity()}")
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Budget optimization endpoint (requires authentication)
class BudgetOptimization(Resource):
    @jwt_required()
    @log_action("Budget Optimization")
    def post(self):
        current_user = get_jwt_identity()
        user_data = users[current_user]

        # Calculate discretionary income
        discretionary_income = user_data['income']
        for expense in user_data['expenses'].values():
            discretionary_income -= expense

        # Allocate funds for goals
        for goal, amount in user_data['goals'].items():
            if amount > discretionary_income:
                return {"message": "Insufficient funds for goal '{}'".format(goal)}, 400
            else:
                discretionary_income -= amount

        # Allocate remaining funds for investments
        for investment, amount in user_data['investments'].items():
            if discretionary_income > 0:
                user_data['investments'][investment] += discretionary_income / len(user_data['investments'])

        # Update user's budget and investment information in the database (simulated)
        users[current_user] = user_data

        # Remove sensitive data from response
        response_data = user_data.copy()
        del response_data['password']  # Remove password from response
        del response_data['email']  # Remove email from response

        return {"message": "Budget optimized successfully", "user_data": response_data}, 200

# Subscription management endpoint (requires authentication)
class Subscription(Resource):
    @jwt_required()
    @log_action("Subscription Update")
    def put(self):
        current_user = get_jwt_identity()
        data = request.get_json()
        new_subscription_plan = data.get('subscription_plan')

        if new_subscription_plan not in subscription_plans:
            return {"message": "Invalid subscription plan"}, 400

        users[current_user]['subscription_plan'] = new_subscription_plan
        return {"message": "Subscription plan updated successfully"}, 200

# Profile management endpoint (requires authentication)
class UserProfile(Resource):
    @jwt_required()
    @log_action("Profile Update")
    def put(self):
        current_user = get_jwt_identity()
        data = request.get_json()

        # Update user's profile information
        for key, value in data.items():
            if key in users[current_user]:
                users[current_user][key] = value

        return {"message": "Profile updated successfully"}, 200

# Password change endpoint (requires authentication)
class ChangePassword(Resource):
    @jwt_required()
    @log_action("Password Change")
    def put(self):
        current_user = get_jwt_identity()
        data = request.get_json()
        new_password = data.get('new_password')

        if not new_password or len(new_password) < 8:  # Enforce password complexity
            return {"message": "New password must be at least 8 characters long"}, 400

        users[current_user]['password'] = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        return {"message": "Password changed successfully"}, 200

# Error handling
@app.errorhandler(Exception)
def handle_error(error):
    logging.error(f"An error occurred: {error}")
    return {"message": "An internal server error occurred"}, 500

api.add_resource(UserLogin, '/login')
api.add_resource(BudgetOptimization, '/budget')
api.add_resource(Subscription, '/subscription')
api.add_resource(UserProfile, '/profile')
api.add_resource(ChangePassword, '/changepassword')
api.add_resource(TwoFactorAuth, '/twofactorauth')
api.add_resource(WhitelistIP, '/whitelistip')

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')
