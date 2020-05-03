import os

from flask import Flask, abort, g, jsonify, request, url_for
from flask_httpauth import HTTPBasicAuth
from flask_restful import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import BadSignature, SignatureExpired
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy.exc import IntegrityError


app = Flask(__name__)
app.config.from_object(os.environ["APP_SETTINGS"])
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_COMMIT_ON_TEARDOWN"] = True

api = Api(app)

db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(300))

    def hash_password(self, password):
        self.password_hash = pwd_context.hash(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=86400):
        s = Serializer(app.config["SECRET_KEY"], expires_in=expiration)
        return s.dumps({"id": self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config["SECRET_KEY"])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = User.query.get(data["id"])
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


@app.route("/api/users", methods=["POST"])
def new_user():
    username = request.json.get("username")
    password = request.json.get("password")
    if username is None or password is None:
        abort(400)
    if User.query.filter_by(username=username).first() is not None:
        abort(400)
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (
        jsonify({"username": user.username}),
        201,
        {"Location": url_for("get_user", id=user.id, _external=True)},
    )


@app.route("/api/all_users", methods=["GET"])
def get_user():
    username = request.headers.get("username")
    password = request.headers.get("password")
    if not verify_password(username, password):
        abort(401)
    json_send = []
    users = User.query.all()
    for user in users:
        json_send.append({"username": user.username})
    return jsonify({"results": json_send})


@app.route("/api/token")
def get_auth_token():
    username = request.headers.get("username")
    password = request.headers.get("password")
    if not verify_password(username, password):
        abort(401)
    token = g.user.generate_auth_token(86400)
    return jsonify({"token": token.decode("ascii"), "duration": 86400})


class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(60), nullable=False)
    text = db.Column(db.String(2000), nullable=False)
    title = db.Column(db.String(100), nullable=False)


class new_message(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("category", type=str)
    parser.add_argument("text", type=str)
    parser.add_argument("title", type=str)

    def post(self):
        username = request.headers.get("username")
        password = request.headers.get("password")
        if not verify_password(username, password):
            abort(401)
        document = self.parser.parse_args(strict=True)
        category = document.get("category")
        text = document.get("text")
        title = document.get("title")

        message = Message(category=category, text=text, title=title)
        db.session.add(message)
        try:
            db.session.commit()
        except IntegrityError as ex:
            abort(400, message=str(ex))

        json_send = {}
        json_send[message.id] = {"category": category, "text": text, "title": title}
        return jsonify(json_send)


class get_all_messages(Resource):
    def get(self):
        messages = Message.query.all()

        json_send = []
        for message in messages:
            json_send.append(
                {
                    "id": message.id,
                    "category": message.category,
                    "text": message.text,
                    "title": message.title,
                }
            )
        return jsonify({"results": json_send})


class get_all_categories(Resource):
    def get(self):
        messages = Message.query.all()
        json_send = []
        for message in messages:
            if message.category not in json_send:
                json_send.append(message.category)
        return jsonify({"results": json_send})


class get_messages_from_category(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("category", type=str)

    def get(self):
        document = self.parser.parse_args(strict=True)
        category = document.get("category")

        messages = Message.query.filter_by(category=category).all()
        json_send = []
        for message in messages:
            json_send.append({"text": message.text, "title": message.title})
        return jsonify({"results": json_send})


class delete_message(Resource):
    def delete(self, _id):
        username = request.headers.get("username")
        password = request.headers.get("password")
        if not verify_password(username, password):
            abort(401)
        query = Message.query.get(_id)
        if not query:
            abort(404)
        db.session.delete(query)
        db.session.commit()
        json_send = {"id": _id}
        return jsonify(json_send)


class Voluntary(db.Model):
    __tablename__ = "voluntary"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    cv = db.Column(db.String(2000), nullable=False)
    bio = db.Column(db.String(2000), nullable=False)
    contact = db.Column(db.String(16), nullable=False)


class new_voluntary(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("name", type=str)
    parser.add_argument("cv", type=str)
    parser.add_argument("bio", type=str)
    parser.add_argument("contact", type=str)

    def post(self):
        username = request.headers.get("username")
        password = request.headers.get("password")
        if not verify_password(username, password):
            abort(401)
        document = self.parser.parse_args(strict=True)
        name = document.get("name")
        cv = document.get("cv")
        bio = document.get("bio")
        contact = document.get("contact")

        voluntary = Voluntary(name=name, cv=cv, bio=bio, contact=contact)
        db.session.add(voluntary)
        try:
            db.session.commit()
        except IntegrityError as ex:
            abort(400, message=str(ex))

        json_send = {}
        json_send[voluntary.id] = {"name": name, "contact": contact}
        return jsonify(json_send)


class get_volunteers(Resource):
    def get(self):
        username = request.headers.get("username")
        password = request.headers.get("password")
        if not verify_password(username, password):
            abort(401)
        volunteers = Voluntary.query.all()
        json_send = []
        for voluntary in volunteers:
            json_send.append(
                {
                    "name": voluntary.name,
                    "cv": voluntary.cv,
                    "bio": voluntary.bio,
                    "contact": voluntary.contact,
                }
            )
        return jsonify({"results": json_send})


api.add_resource(get_all_messages, "/api/all_messages")
api.add_resource(new_message, "/api/new_message")
api.add_resource(delete_message, "/api/delete_message")
api.add_resource(get_all_categories, "/api/all_categories")
api.add_resource(get_messages_from_category, "/api/message_from_category")
api.add_resource(new_voluntary, "/api/new_voluntary")
api.add_resource(get_volunteers, "/api/get_volunteers")

if __name__ == "__main__":
    app.run(debug=True)
