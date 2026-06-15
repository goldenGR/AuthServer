# golden's AuthServer

> This is an "Login with Minecraft" backend system.

This server is made to let minecraft clients login, authenticate with the microsoft servers and if the authentication handshake is proper, to give them a login code where then it can be use inside any app for the "Login with Minecraft" feature

# Requirements

- Python 3.11+
- Dependencies from `requirements.txt`

# Customizing

You can customize the server by modifying the ``server.properties`` file.

#### Keys

KeyName | Description |
--------|-------------|
motd    | The MOTD of the server|
kickmsg | The message send to players containing the login code
mp      | Max players displayed for the server
op      | Online players displayed by the server

# Setting up

After you have finished with customizing the ``server.properties`` file, you can start off by creating the ``logToken`` function under the ``./src/logTokens`` file.

> Note: currently it doesnt do anyting as you need to set it up with your backend database!

#### Format
```py
def logToken(username, token):
    # Add here your database loging code
    pass
```

After saving the data to your database you can pull back the code when registering (e.x. /connect {code} discord bot command)

# Credits

Credits to Me ( [HG]golden ) and love to HG