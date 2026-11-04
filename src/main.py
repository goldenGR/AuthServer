"""
    golden's AuthServer by Odysseas Chryssos all right reserved | ody (dot) chryssos (at) gmail (dot) com
    Available for commercial use under goldensAuth License v1.0 - goldenCube Software Foundation
    License can be found at /license & licenses.goldencube.dev/goldensAuth-License/v1.0
"""

from os import urandom, path
import secrets
import string
from quarry.net.server import ServerFactory, ServerProtocol, cached_property
from quarry.types.chat import Message
from twisted.internet import reactor
from twisted.python import log
from twisted.internet.threads import deferToThread
import time
from collections import defaultdict
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from logTokens import logToken
import configparser
import base64
import requests
import hashlib

key = RSA.generate(1024)

# Load config file
config = configparser.RawConfigParser()
config.read(path.abspath('server.properties'), encoding='utf-8')

iconPath = config.get('ServerMessages', 'faviconPath', fallback="icon.png")
with open(iconPath, "rb") as image_file:
    encoded_string = base64.b64encode(image_file.read()).decode('utf-8')

favicon_uri = f"data:image/png;base64,{encoded_string}"

# Logging functions
LOGGING_ENABLED = bool(config.getboolean('Propperties', 'logging', fallback=False))
log.startLogging(sys.stdout)
def logg(*args, **kwargs):
    if LOGGING_ENABLED:
        print("[AuthServer] ",*args, **kwargs)

# Generate minecraft server id based on mojang's auth algo
def generate_server_id(base_server_id: str, public_key: bytes, secret_key: bytes) -> str:
    digest = hashlib.sha1(
        base_server_id.encode("iso-8859-1")
        + secret_key
        + public_key
    ).digest()

    value = int.from_bytes(digest, byteorder="big", signed=True)

    return format(value, "x")

# AuthServer protocol implementation
class AuthServerProtocol(ServerProtocol):
    def connection_lost(self, reason=None):
        ip = self.transport.getPeer().host
        if self.factory.peer_connections[ip] > 0:
            self.factory.peer_connections[ip] -= 1
        super().connection_lost(reason)
    
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

    def checkAuthServer(self, username, shared_secret):
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

        self.UUID = None
        if response.status_code == 200:
            data = response.json()
            self.UUID = data.get("id")
        logg("Hash:", server_id)
        logg("Status:", response.status_code)
        logg("Body:", response.text)
        return response.status_code == 200

    def packet_login_encryption_response(self, buff):
        ip = self.transport.getPeer().host
        if self.factory.isIpRateLimited(ip):
            self.close(Message.from_string("You are being rate limited. Please try again later."))
            return
        
        cipher = PKCS1_v1_5.new(self.factory.private_key)
        shared_secret_enc = buff.unpack_byte_array()
        verify_token_enc = buff.unpack_byte_array()

        shared_secret = cipher.decrypt(shared_secret_enc, None)
        verify_token = cipher.decrypt(verify_token_enc, None)

        if shared_secret is None or verify_token is None or len(shared_secret) != 16 or len(verify_token) != 4:
            self.close(Message.from_string("Client handshake failed"))
            return

        print("Client responded!")
        logg(f"VF: {verify_token} SS: {shared_secret}")

        if verify_token != self.verify_token:
            print("Token mismatch!")
            self.close(Message.from_string("Authentication failed"))
            return

        self.cipher.enable(shared_secret)

        d = deferToThread(self.checkAuthServer, self.display_name, shared_secret)
        d.addCallback(self._auth_done)
        def on_auth_error(failure):
            logg(f"Auth error: {failure.getErrorMessage()}")
            logg(failure.getTraceback())   # full traceback, optional
            self.close(Message.from_string("Authentication error"))

        d.addErrback(on_auth_error)

    def _auth_done(self, ok):
        if ok:
            self.player_joined()
        else:
            self.close(Message.from_string("Authentication failed"))

    def player_joined(self):         
        code = ''.join(
            secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8)
        )

        try:
            # logToken(self.UUID, code)
            d = deferToThread(logToken, self.UUID, code)
            d.addCallback(
                lambda c: self.close(
                    Message.from_string(
                        config.get('ServerMessages', 'kickmsg', fallback="§6 You have authenticated! \n §3 Verification Code: {code}").replace("{code}", code).replace("\\n", "\n")
                        )
                    )
            )
            d.addErrback(
                lambda e: self.close(
                    Message.from_string("Internal server error")
                    )
                )
        except Exception as e:
            logg(f"Error logging token for UUID {self.UUID}: {e}")
            self.close(Message.from_string("Internal server error"))
            return

    def packet_status_request(self, buff):
            protocol_version = self.factory.force_protocol_version
            if protocol_version is None:
                protocol_version = self.protocol_version
    
            d = {
                "description": {"text": self.factory.motd},
                "players": {
                    "online": self.factory.online_players,
                    "max": self.factory.max_players,
                },
                "version": {
                    "name": "1.8.9",
                    "protocol": protocol_version
                }
            }

            d['favicon'] = favicon_uri
    
            self.send_packet("status_response", self.buff_type.pack_json(d))
    


# Auth server builder.
class AuthServerFactory(ServerFactory):
    RATE_WINDOW = int(config.get('ConnectionConfig', 'rateWindow', fallback=60))
    MAX_ATTEMPTS = int(config.get('ConnectionConfig', 'maxAttempts', fallback=5))
    MAX_PERPEER = int(config.get('ConnectionConfig', 'maxPerPeer', fallback=3))

    protocol = AuthServerProtocol
    online_mode = False

    motd = f"{config.get('ServerMessages', 'motd', fallback='Verification Server').replace('\\n', '\\n')} \n §6Powered by goldens AuthServer"
    max_players = int(config.get('ServerMessages', 'mp', fallback=500))
    online_players = int(config.get('ServerMessages', 'op', fallback=67))
            
    def __init__(self):
        super().__init__()
        self.attempt_log = defaultdict(list)
        self.peer_connections = defaultdict(int)

    def isIpRateLimited(self, ip) -> bool:
        now = time.time()
        attempts = self.attempt_log[ip]
        attempts[:] = [t for t in attempts if now - t < self.RATE_WINDOW]
        if len(attempts) >= self.MAX_ATTEMPTS:
            return True
        attempts.append(now)
        return False

    def buildProtocol(self, addr):
        ip = addr.host
        if self.peer_connections[ip] >= self.MAX_PERPEER:
            return None
        self.peer_connections[ip] += 1
        return ServerFactory.buildProtocol(self, addr)

if __name__ == "__main__":
    factory = AuthServerFactory()

    factory.listen("0.0.0.0", 25565)
    factory.private_key = key
    factory.public_key = key.publickey().exportKey("DER")

    print("Auth server running on port 25565")

    reactor.run()
    print("online_mode =", factory.online_mode)