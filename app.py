import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask_restful import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

app = Flask(__name__)
app.config.from_object(os.environ['APP_SETTINGS'])
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

api = Api(app)

db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(300))

    def hash_password(self, password):
        self.password_hash = pwd_context.hash(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=86400):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = User.query.get(data['id'])
        return user


@auth.verify_password
def verify_password(username_or_token, password):
    user = User.verify_auth_token(username_or_token)
    if not user:
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)
    if User.query.filter_by(username=username).first() is not None:
        abort(400)
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(86400)
    return jsonify({'token': token.decode('ascii'), 'duration': 86400})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(60), nullable=False)
    text = db.Column(db.String(500), nullable=False)


parser = reqparse.RequestParser()
parser.add_argument("category", type=str)
parser.add_argument("text", type=str)


@app.route("/api/new_message", methods=["POST"])
@auth.login_required
def create_message():
    document = parser.parse_args(strict=True)
    category = document.get("category")
    text = document.get("text")

    message = Message(category=category, text=text)
    db.session.add(message)
    try:
        db.session.commit()
    except IntegrityError as ex:
        abort(400, message=str(ex))

    json_send = {}
    json_send[message.id] = {"category": category, "text": text}
    return jsonify(json_send)


class get_all_messages(Resource):
    def get(self):
        messages = Message.query.all()

        json_send = {}
        for message in messages:
            json_send[message.id] = {
                "category": message.category,
                "text": message.text,
            }
        return jsonify(json_send)


api.add_resource(get_all_messages, "/api/all_messages")

if __name__ == '__main__':
    app.run(debug=True)
