from flask import Flask, jsonify, request
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

from models.user import User

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql:///root:admin123@127.0.0.1:3306/flask-crud'

login_manager = LoginManager()

db.init_app(app)
login_manager.init_app(app)
# view login
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
  return User.query.get(user_id)

@app.route('/user', methods=['POST'])
def create_user():
	data = request.json

	username = data['username']
	password = data['password']

	if username and password:
		found_user = User.query.filter_by(username=username).first()

		if found_user:
			return jsonify({'message': 'User already exists'}), 400

		hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
		new_user = User(username=username, password=hashed_password, role='user')

		db.session.add(new_user)
		db.session.commit()

		return jsonify({'message': 'User created successfully'}), 201

	return jsonify({'message':'Invalid credentials'}), 400


@app.route('/login', methods=['POST'])
def login():
  data = request.json

  username = data['username']
  password = data['password']

  if username and password:
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
      login_user(user)
      print(current_user.is_authenticated)

      return jsonify({'message': 'User authenticated successfully'}), 201

  return jsonify({'message': 'Invalid credentials'}), 400

@app.route('/logout', methods=['GET'])
@login_required # this route is private (requires authenticated user)
def logout():
  logout_user()
  return jsonify({'message': 'User logout successfully'})

@app.route('/user/<int:user_id>', methods=['GET'])
@login_required
def get_user_by_id(user_id:int):
  user = User.query.get(user_id)

  if user:
    return jsonify({ 'username': user.username }), 200

  return jsonify({'message': 'User not found'}), 404

@app.route('/user/<int:user_id>', methods=['PUT'])
@login_required
def update_user_by_id(user_id: int):
	data = request.json
	user = User.query.get(user_id)

	if user_id != current_user.id and current_user.role == 'user':
		return jsonify({'message': 'Action not allowed'}), 403

	if user and data['password']:
		user.password = data['password']
		db.session.commit()

		return jsonify({'message': f'User {user_id} updated successfully'})

	return jsonify({'message': 'User not found'}), 404

@app.route('/user/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
  user = User.query.get(user_id)

  if current_user.role != 'admin':
    return jsonify({'message': 'Action not allowed'}), 403

  if user_id == current_user.id:
    return jsonify({'message': 'It\'s not allowed to delete yourself'}), 403

  if user:
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': f'User {user_id} deleted successfully'})

  return jsonify({'message': 'User not found'}), 404

@app.route('/hello-world', methods=['GET'])
def hello_world():
  return 'Hello World'

if app == '__main__':
  app.run(debug=True)
