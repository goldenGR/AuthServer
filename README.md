# golden's AuthServer
> Version: 1.6

> This is an "Login with Minecraft" backend system.

This server is made to let minecraft clients login, authenticate with the microsoft servers and if the authentication handshake is proper, to give them a login code where then it can be use inside any app for the "Login with Minecraft" feature

# Requirements

- Python 3.12+
- Dependencies from `requirements.txt`

# Customizing

You can customize the server by modifying the ``server.properties`` file.

#### Keys

KeyName     | Description |                                         | Section |
------------|-------------|-----------------------------------------|---------|
motd        | The MOTD of the server                                | [ServerMessages]
kickmsg     | The message send to players containing the login code | [ServerMessages]
mp          | Max players displayed for the server                  | [ServerMessages]
op          | Online players displayed by the server                | [ServerMessages]
rateWindow  | The time before ip block resets, in seconds           | [ConnectionConfig]
maxAttempts | Max connect attempts per IP                           | [ConnectionConfig]

# Setting up

After you have finished with customizing the ``server.properties`` file, you can start off by creating the ``logToken`` function under the ``./src/logTokens`` file.

> Note: currently it doesnt do anyting as you need to set it up with your backend database! Dont forget to add proper expiration of tokens :3

#### Format
```py
def logToken(UUID, token):
    # Add here your database loging code
    pass
```

After saving the data to your database you can pull back the code when registering (e.x. /connect {code} discord bot command)

# Credits

Credits to Me ( [HG]golden ) and love to HG