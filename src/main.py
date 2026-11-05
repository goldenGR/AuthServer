"""
    golden's AuthServer by Odysseas Chryssos all right reserved | ody (dot) chryssos (at) gmail (dot) com
    Available for commercial use under goldensAuth License v1.0 - goldenCube Software Foundation
    License can be found at /license & licenses.goldencube.dev/goldensAuth-License/v1.0
"""

from os import urandom, path
from pathlib import Path
import secrets
import string
import uuid
from quarry.net.server import ServerFactory, ServerProtocol
from quarry.types.chat import Message
from quarry.data import packets as qpackets
from quarry.net.protocol import ProtocolError, protocol_modes
from twisted.internet import reactor
from twisted.python import log
from twisted.internet.threads import deferToThread
from twisted.internet.task import LoopingCall
import time
from collections import defaultdict
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import struct
from logTokens import logToken
import configparser
import base64
import requests
import hashlib

key = RSA.generate(2048)
BASE_DIR = Path(__file__).resolve().parent

# Load config file
config = configparser.RawConfigParser()
config.read(path.abspath(f'{BASE_DIR / "server.properties"}'), encoding='utf-8')

# Load favicon icon.
iconPath = BASE_DIR / config.get('ServerMessages', 'faviconPath', fallback="icon.png")
with open(iconPath, "rb") as image_file:
    encoded_string = base64.b64encode(image_file.read()).decode('utf-8')

favicon_uri = f"data:image/png;base64,{encoded_string}"

# Logging functions
LOGGING_ENABLED = bool(config.getboolean('Properties', 'logging', fallback=False))
log.startLogging(sys.stdout)
def logg(*args, **kwargs):
    if LOGGING_ENABLED:
        print("[AuthServer] ",*args, **kwargs)

# Constants for protocol handling
FALLBACK_MODES = ("init", "status", "login")
KNOWN_VERSIONS = sorted({k[0] for k in qpackets.packet_names
                         if k[1] == "login" and isinstance(k[0], int)})
BASE_VERSION = KNOWN_VERSIONS[-1]   # newest version quarry knows

# Generate minecraft server id based on mojang's auth algo, taken from minecraft wiki.
def generateServerId(base_server_id: str, public_key: bytes, secret_key: bytes) -> str:
    digest = hashlib.sha1(
        base_server_id.encode("iso-8859-1")
        + secret_key
        + public_key
    ).digest()

    value = int.from_bytes(digest, byteorder="big", signed=True)

    return format(value, "x")

# AuthServer protocol implementation
class AuthServerProtocol(ServerProtocol):

    # Copied directly from quarry's ServerProtocol, with some modifications to support newer versions.
    def packet_handshake(self, buff):
            p_protocol_version  = buff.unpack_varint()
            p_connect_host      = buff.unpack_string()
            p_connect_port      = buff.unpack("H")
            p_protocol_mode     = buff.unpack_varint()

            mode = protocol_modes.get(p_protocol_mode)
            if mode is None and p_protocol_mode == 3:
                mode = "login"
            if mode is None:
                self.close("Unsupported handshake mode")
                return
            self.switch_protocol_mode(mode)

            if mode == "login":
                # version check intentionally removed: accept any protocol version
                if len(self.factory.players) >= self.factory.max_players:
                    self.close("Server is full")
                    return
                self.factory.players.add(self)

            self.protocol_version = p_protocol_version
            try:
                self.buff_type = self.factory.get_buff_type(p_protocol_version)
            except Exception:
                # unknown version: borrow the newest version quarry knows
                self.buff_type = self.factory.get_buff_type(BASE_VERSION)
            self.connect_host = p_connect_host
            self.connect_port = p_connect_port

    # Custom logic to support newer versions of Minecraft through old packets names.
    def get_packet_name(self, ident) -> str:
        key = (self.protocol_version, self.protocol_mode, self.recv_direction, ident)
        if key not in qpackets.packet_names and self.protocol_mode in FALLBACK_MODES:
            key = (BASE_VERSION,) + key[1:]
        try:
            return qpackets.packet_names[key]
        except KeyError:
            raise ProtocolError("No name known for packet: %s" % (key,))

    def get_packet_ident(self, name) -> int:
        key = (self.protocol_version, self.protocol_mode, self.send_direction, name)
        if key not in qpackets.packet_idents and self.protocol_mode in FALLBACK_MODES:
            key = (BASE_VERSION,) + key[1:]
        try:
            return qpackets.packet_idents[key]
        except KeyError:
            raise ProtocolError("No ident known for packet: %s" % (key,))
    
    def connection_lost(self, reason=None):
        ip = getattr(self, "ip", None)
        if ip is not None:
            if self.factory.peer_connections[ip] > 0:
                self.factory.peer_connections[ip] -= 1
        super().connection_lost(reason)

    def unpack_array(self, buff) -> bytes:
        if self.protocol_version >= 47:
            return buff.read(buff.unpack_varint(max_bits=16))
        return buff.read(buff.unpack("h"))

    def pack_array(self, d) -> bytes:
        if self.protocol_version >= 47:
            return self.buff_type.pack_varint(len(d), max_bits=16) + d
        return self.buff_type.pack("h", len(d)) + d

    # <- Auth handling functions ->
    def onAuthError(self, failure): # Handle auth errors, kick player accordingly
            logg(f"Auth error: {failure.getErrorMessage()}")
            if failure.check(RuntimeError):
                msg = str(failure.value)
                if msg == "Authentication service unavailable":
                    self.close(Message.from_string("Authentication servers are down."))
                elif msg == "Authentication service rate limited":
                    self.close(Message.from_string("Authentication servers are being rate limited. Please try again later."))
                elif msg == "Invalid response from authentication service: missing 'id' field" or msg == "Invalid UUID received from authentication service": 
                    self.close(Message.from_string("Invalid player data received from authentication service."))
                else:
                    self.close(Message.from_string("Authentication error"))
            else:
                self.close(Message.from_string("Authentication error"))

    # Actuall auth check through mojangs server.
    def checkAuthServer(self, username, shared_secret) -> bool:
        self.UUID = None
        server_id = generateServerId(
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

        logg("Hash:", server_id)
        logg("Status:", response.status_code)
        logg("Body:", response.text)

        if response.status_code == 200:
            data = response.json()
            player_uuid = data.get("id")
            if not isinstance(player_uuid, str):
                raise RuntimeError("Invalid response from authentication service: missing 'id' field")
                

            try:
                uuid.UUID(hex=player_uuid)
            except ValueError:
                raise RuntimeError("Invalid UUID received from authentication service")

            self.UUID = player_uuid
            return True

        if response.status_code == 204:
            return False

        if response.status_code == 429:
            raise RuntimeError("Authentication service rate limited")

        if response.status_code >= 500:
            raise RuntimeError("Authentication service unavailable")

        return False

    # Where the magic starts. Aka here is where the client sends the login start packet, and server respond with the encryption request.
    def packet_login_start(self, buff):
        # Block the ip if rate limited.
        self.ip = self.transport.getPeer().host
        if self.factory.isIpRateLimited(self.ip):
            self.close(Message.from_string("You are being rate limited. Please try again later."))
            return
        
        self.display_name = buff.unpack_string()
        self.chat_public_key = None
        if 759 <= self.protocol_version <= 760:  # 1.19 - 1.19.2 may send the player's chat key
            if buff.unpack("?"):
                buff.unpack("q")                                 # key expiry
                self.chat_public_key = self.unpack_array(buff)   # player's public key (DER)
                self.unpack_array(buff)                          # mojang's signature of the key
        buff.read()
        self.verify_token = urandom(4)

        fields = [
            self.buff_type.pack_string("GLORY2HATEGROUP"),
            self.pack_array(self.factory.public_key),
            self.pack_array(self.verify_token),
        ]
        if self.protocol_version >= 766:          # 1.20.5+
            fields.append(self.buff_type.pack("?", True))
        self.send_packet("login_encryption_request", *fields)

    # Server response to the starting packet, and start handshake
    def packet_login_encryption_response(self, buff):
        cipher              = PKCS1_v1_5.new(self.factory.private_key)
        shared_secret_enc   = self.unpack_array(buff)

        if 759 <= self.protocol_version <= 760:  # 1.19 - 1.19.2
            if buff.unpack("?"):                 # has verify token
                verify_token_enc = self.unpack_array(buff)
            else:
                salt = buff.unpack("q")
                signature = self.unpack_array(buff)
                verify_token_enc = None          # skip token check; the Mojang hasJoined check still authenticates
        else:
            verify_token_enc = self.unpack_array(buff)

        shared_secret   = cipher.decrypt(shared_secret_enc, None)

        if shared_secret is None or len(shared_secret) != 16:
            self.close(Message.from_string("Client handshake failed"))
            return

        print("Client responded!")

        if verify_token_enc is not None:
            verify_token = cipher.decrypt(verify_token_enc, None)
            if verify_token is None or verify_token != self.verify_token:
                print("Token mismatch!")
                self.close(Message.from_string("Authentication failed"))
                return
        else:
            # 1.19-1.19.2 clients with chat keys sign (verify token + salt) with their chat key instead
            if not self.checkSaltSignature(salt, signature):
                print("Signature mismatch!")
                self.close(Message.from_string("Authentication failed"))
                return

        self.cipher.enable(shared_secret)

        d = deferToThread(self.checkAuthServer, self.display_name, shared_secret)
        d.addCallback(self._auth_done)
        d.addErrback(self.onAuthError)

    def checkSaltSignature(self, salt, signature) -> bool:
        if self.chat_public_key is None:
            return False
        try:
            key = RSA.import_key(self.chat_public_key)
            h = SHA256.new(self.verify_token + struct.pack(">q", salt))
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError, IndexError):
            return False

    def _auth_done(self, ok):
        if ok:
            self.player_joined()
        else:
            self.close(Message.from_string("Authentication failed"))

    def player_joined(self):         
        code = ''.join(
            secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8)
        )

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

    def packet_status_request(self, buff):
            protocol_version = self.factory.force_protocol_version
            if protocol_version is None:
                protocol_version = self.protocol_version
    
            d = {
                "description": {"text": self.factory.motd},
                "players": {
                    "online": self.factory.online_players,
                    "max": self.factory.max_players,
                    "sample": [
                        {
                            "name": "goldenGR",
                            "id": "7d6f5d76-64a8-4d29-bfa5-5ce2f6055a49"
                        }
                    ]
                },
                "version": {
                    "name": config.get(
                                "ServerMessages",
                                "versionName",
                                fallback="goldens Auth Server"
                    ),
                    "protocol": protocol_version
                },
                "enforcesSecureChat": False
            }

            d['favicon'] = favicon_uri
    
            self.send_packet("status_response", self.buff_type.pack_json(d))
    


# Auth server builder.
class AuthServerFactory(ServerFactory):
    RATE_WINDOW     = int(config.get('ConnectionConfig', 'rateWindow', fallback=60))
    MAX_ATTEMPTS    = int(config.get('ConnectionConfig', 'maxAttempts', fallback=5))
    MAX_PERPEER     = int(config.get('ConnectionConfig', 'maxPerPeer', fallback=3))

    if RATE_WINDOW <= 0:
        raise ValueError("rateWindow must be greater than zero")

    if MAX_ATTEMPTS <= 0:
        raise ValueError("maxAttempts must be greater than zero")

    if MAX_PERPEER <= 0:
        raise ValueError("maxPerPeer must be greater than zero")

    protocol        = AuthServerProtocol
    online_mode     = False

    motd            = f"{config.get('ServerMessages', 'motd', fallback='Verification Server').replace('\\n', '\n')} \n §6Powered by goldens AuthServer"
    max_players     = int(config.get('ServerMessages', 'mp', fallback=500))
    online_players  = int(config.get('ServerMessages', 'op', fallback=67))
            
    def __init__(self):
        super().__init__()
        self.attempt_log        = defaultdict(list)
        self.peer_connections   = defaultdict(int)
        self.cleanup_loop = LoopingCall(self.cleanupRateLimit)
        self.cleanup_loop.start(10, now=False)

    def cleanupRateLimit(self):
        now = time.time()

        for ip, attempts in list(self.attempt_log.items()):
            attempts[:] = [
                t for t in attempts
                if now - t < self.RATE_WINDOW
            ]

            if not attempts:
                del self.attempt_log[ip]

        for ip, connections in list(self.peer_connections.items()):
            if connections <= 0:
                del self.peer_connections[ip]

    def isIpRateLimited(self, ip) -> bool:
        now = time.time()
        attempts = self.attempt_log[ip]
        attempts[:] = [t for t in attempts if now - t < self.RATE_WINDOW]
        if len(attempts) >= self.MAX_ATTEMPTS:
            return True
        attempts.append(now)
        return False

    def buildProtocol(self, addr) -> AuthServerProtocol:
        ip = addr.host
        if self.peer_connections[ip] >= self.MAX_PERPEER:
            return None
        self.peer_connections[ip] += 1
        p = ServerFactory.buildProtocol(self, addr)
        if p is None:
            self.peer_connections[ip] -= 1
            return None
        p.ip = ip
        return p

if __name__ == "__main__":
    factory = AuthServerFactory()

    factory.listen("0.0.0.0", 25565)
    factory.private_key = key
    factory.public_key = key.publickey().exportKey("DER")

    print("Auth server running on port 25565")

    reactor.run()
    print("online_mode =", factory.online_mode)