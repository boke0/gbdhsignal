from flask import Flask, jsonify, request
from flask_restful import Resource, Api
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False
db = SQLAlchemy(app)
api = Api(app)


class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    participants = db.relationship('Participant', back_populates='room')
    chats = db.relationship('Chat', back_populates='room')
    created_at = db.Column(db.DateTime)

    @classmethod
    def create_room(cls, name, participants):
        room = Room()
        room.name = name,
        room.participants = participants,
        room.created_at = datetime()
        return room


class Participant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_key = db.Column(db.Text)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'))
    room = db.relationship('Room', back_populates='participants')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', back_populates='participants')

    @classmethod
    def from_user(cls, user):
        participant = Participant()
        participant.user = user
        return participant


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    init_public_key = db.Column(db.Text)
    participants = db.relationship('Participant', back_populates='user')

    @classmethod
    def create(cls, name, init_public_key):
        user = User()
        user.name = name
        user.init_public_key = init_public_key
        return user


class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    posted_at = db.Column(db.DateTime)
    meta = db.Column(db.Text)
    text = db.Column(db.Text)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'))
    room = db.relationship('Room', back_populates='participants')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User')


class RoomsResource(Resource):
    def get(self):
        _, id = request.headers.get('Authorization').split()
        user = db.session.query(User).filter(User.id == int(id))
        return jsonify(
            user.participants.map(lambda participant: participant.room)
        )

    def post(self):
        name = request.json['name']
        user_ids = request.json['user_ids']
        users = db.session.query(User).filter(User.id.in_(user_ids))
        room = Room.create_room(name, users)
        db.session.add(room)
        db.session.commit()
        return jsonify(room)


class RoomResource(Resource):
    def get(self, room_id):
        room = db.session.query(Room).filter(Room.id == room_id)
        return jsonify(room)


class ChatResource(Resource):
    def get(self, room_id):
        since = int(request.args['since']) or 0
        chats = db.session.query(Chat).filter(
            Chat.room_id == room_id,
            Chat.id > since
        )
        return jsonify(chats)

    def post(self, room_id):
        _, id = request.headers.get('Authorization').split()
        user = db.session.query(User).filter(User.id == int(id))
        room = db.session.query(Room).filter(Room.id == room_id)
        room.post_chat(user, request.json['meta'], request.json['text'])
        return jsonify()


class UsersResource(Resource):
    def get(self):
        users = User.query.all()
        return jsonify(users)

    def post(self):
        name = request.json['name']
        init_public_key = request.json['init_public_key']
        user = User.create(name, init_public_key)
        db.session.add(user)
        db.session.commit()
        return jsonify(user)


class UserResource(Resource):
    def get(self, user_id):
        user = User.query.filter(User.id == user_id)
        return jsonify(user)


api.add_resource(RoomsResource, '/rooms')
api.add_resource(RoomResource, '/rooms/<number>')
api.add_resource(ChatResource, '/rooms/<number>/chat')
api.add_resource(UsersResource, '/users')
api.add_resource(UserResource, '/users/<number>')


def run():
    app.run(host='0.0.0.0', port=8080, threaded=False)
