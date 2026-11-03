"""
    golden's AuthServer by Odysseas Chryssos all right reserved | ody (dot) chryssos (at) gmail (dot) com
    Available for commercial use under MIT License
"""

from os import urandom
import random
import string
from quarry.net.server import ServerFactory, ServerProtocol
from quarry.types.chat import Message
from twisted.internet import reactor
from twisted.python import log
from twisted.internet.threads import deferToThread
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from logTokens import logToken
import configparser
import base64
import requests

import hashlib
key = RSA.generate(1024)
config = configparser.RawConfigParser()
config.read('server.properties', encoding='utf-8')
with open(config.get('ServerMessages', 'faviconPath').replace("\\n", "\n"), "rb") as f:
    FAVICON = "data:image/png;base64," + base64.b64encode(f.read()).decode("ascii")

log.startLogging(sys.stdout)

def generate_server_id(base_server_id: str, public_key: bytes, secret_key: bytes) -> str:
    digest = hashlib.sha1(
        base_server_id.encode("iso-8859-1")
        + secret_key
        + public_key
    ).digest()

    # Java's BigInteger(byte[]) treats the bytes as signed, big-endian.
    value = int.from_bytes(digest, byteorder="big", signed=True)

    return format(value, "x")

class AuthServerProtocol(ServerProtocol):
    
    def packet_login_start(self, buff):
        self.display_name = buff.unpack_string()

        self.verify_token = urandom(4)

        pack_array = lambda d: (
            self.buff_type.pack_varint(len(d), max_bits=16) + d
        )

        self.send_packet(
            "login_encryption_request",
            self.buff_type.pack_string("GLORY2HATEGROUP"),   # GLORY2HATEGROUP       
            pack_array(self.factory.public_key),     
            pack_array(self.verify_token)           
        )

    def checkAuthServer(self, username, ip, shared_secret):
        server_id = generate_server_id(
            "GLORY2HATEGROUP",
            self.factory.public_key,
            shared_secret
        )

        url = "https://sessionserver.mojang.com/session/minecraft/hasJoined"
        params = {
                "username": username,
                "serverId": server_id,
        }
        response = requests.get(
            url,
            params=params,
            timeout=10
        )
        print("Public IP:", ip)
        print("Hash:", server_id)
        print("Status:", response.status_code)
        print("Body:", response.text)
        return response.status_code == 200

    def packet_login_encryption_response(self, buff):
        cipher = PKCS1_v1_5.new(self.factory.private_key)
        shared_secret_enc = buff.unpack_byte_array()
        verify_token_enc = buff.unpack_byte_array()

        shared_secret = cipher.decrypt(shared_secret_enc, None)
        verify_token = cipher.decrypt(verify_token_enc, None)

        print("Client responded!")
        print(f"VF: {verify_token} SS: {shared_secret}")

        if verify_token != self.verify_token:
            print("Token mismatch!")
            self.close("Authentication failed")
            return

        self.cipher.enable(shared_secret)

        self.cipher.enable(shared_secret)
        d = deferToThread(self.checkAuthServer, self.display_name,
                        self.transport.getPeer().host, shared_secret)
        d.addCallback(self._auth_done)
        d.addErrback(lambda f: self.close("Authentication error"))

    def _auth_done(self, ok):
        if ok:
            self.player_joined()
        else:
            self.close("Authentication failed")
    def player_joined(self):
                
        code = ''.join(
            random.choices(
                string.ascii_uppercase + string.digits,
                k=8
            )
        )

        print(f"{self.display_name} joined. Code: {code}")

        self.close(
            Message.from_string(
                config.get('ServerMessages', 'kickmsg').replace("{code}", code).replace("\\n", "\n")
            )
        )

        logToken( self.display_name, code)


class AuthServerFactory(ServerFactory):
    protocol = AuthServerProtocol
    online_mode = False

    motd = f"{config.get('ServerMessages', 'motd').replace("\\n", "\n")} \n §6Powered by goldens AuthServer"
    max_players = int(config.get('ServerMessages', 'mp'))
    online_players = int(config.get('ServerMessages', 'op'))

    def packet_status_request(self, buff):
        protocol_version = self.factory.force_protocol_version
        if protocol_version is None:
            protocol_version = self.protocol_version

        d = {
            "description": {"text": self.factory.motd},
            "players": {
                "online": self.factory.online_players,
                "max": self.factory.max_players,
                "sample": []
            },
            "version": {
                "name": "1.8.9",
                "protocol": protocol_version
            }
        }

        d["icon"] = FAVICON

        print("STATUS DEBUG:", d["players"], "| favicon len:", len(d.get("icon", "")))
        self.send_packet("status_response", self.buff_type.pack_json(d))


if __name__ == "__main__":
    factory = AuthServerFactory()

    factory.listen("0.0.0.0", 25565)
    factory.private_key = key
    factory.public_key = key.publickey().exportKey("DER")

    print("Auth server running on port 25565")

    reactor.run()
    print("online_mode =", factory.online_mode)