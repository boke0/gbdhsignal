import json
import requests
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP384R1


def post(url, authorization, data):
    response = requests.post(
        url,
        json=json.dumps(data)
    )
    return response.json


def get(url, authorization):
    response = requests.get(
        url,
        headers={
            'Authorization': authorization
        }
    )
    return response.json


class Client:
    def __init__(
        self,
        name
    ):
        self.name = name
        self.init_private_key = generate_private_key(SECP384R1)
        self.rooms = dict()

    def get_init_public_key(self):
        return self.init_private_key.public_key()


class Room:
    def __init__(
        self,
        name,
        participants,
        chats=[],
    ):
        self.name = name
        self.participants = participants
        self.chats = chats


class Chat:
    def __init__():
        pass


def run():
    pass
