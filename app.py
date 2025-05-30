from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime, timedelta
import jwt
from functools import wraps # Import wraps for the decorator

app = Flask(__name__)
CORS(app)  # Enable CORS for all origins (for development)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_super_secret_key'  # <<<< CHANGE THIS IN PRODUCTION!
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key' # <<<< ANOTHER SECRET KEY FOR JWT, CHANGE THIS!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1) # Token expiry

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    tasks = db.relationship('Task', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_description = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Task {self.task_description}>'

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'task_description': self.task_description,
            'completed': self.completed,
            'created_at': self.created_at.isoformat()
        }

# --- JWT Helper Functions ---
def generate_token(user_id, username):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return {'message': 'Token has expired', 'error': True}
    except jwt.InvalidTokenError:
        return {'message': 'Invalid token', 'error': True}

# --- Authentication Decorator ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = decode_token(token)
            if data and data.get('error'):
                return jsonify({'message': data['message']}), 401

            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# --- API Endpoints ---

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'Missing username, email, or password'}), 400

    # Basic server-side validation
    if len(username) < 3:
        return jsonify({'message': 'Username must be at least 3 characters long'}), 400
    if not isinstance(email, str) or '@' not in email or '.' not in email:
        return jsonify({'message': 'Invalid email format'}), 400
    if len(password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters long'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 409

    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    identifier = data.get('identifier') # Can be username or email
    password = data.get('password')

    if not identifier or not password:
        return jsonify({'message': 'Missing identifier or password'}), 400

    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier)
    ).first()

    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = generate_token(user.id, user.username)
    return jsonify({'message': 'Login successful', 'token': token}), 200

@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks(current_user):
    tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.created_at.asc()).all()
    return jsonify({'tasks': [task.to_dict() for task in tasks]}), 200

@app.route('/tasks', methods=['POST'])
@token_required
def add_task(current_user):
    data = request.get_json()
    task_description = data.get('task_description')

    if not task_description:
        return jsonify({'message': 'Task description is required'}), 400

    new_task = Task(user_id=current_user.id, task_description=task_description)
    db.session.add(new_task)
    db.session.commit()

    return jsonify({'message': 'Task added successfully', 'task': new_task.to_dict()}), 201

@app.route('/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(current_user, task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()

    if not task:
        return jsonify({'message': 'Task not found or unauthorized'}), 404

    data = request.get_json()
    # This endpoint now handles both 'completed' and 'task_description' updates
    if 'task_description' in data:
        new_description = data['task_description'].strip()
        if not new_description:
            return jsonify({'message': 'Task description cannot be empty'}), 400
        task.task_description = new_description
    if 'completed' in data:
        task.completed = data['completed']

    db.session.commit()
    return jsonify({'message': 'Task updated successfully', 'task': task.to_dict()}), 200

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user, task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()

    if not task:
        return jsonify({'message': 'Task not found or unauthorized'}), 404

    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted successfully'}), 200

if __name__ == '__main__':
    # This block ensures tables are created when you run app.py directly.
    with app.app_context():
        db.create_all()
    app.run(debug=True) # debug=True is for development, set to False in production
