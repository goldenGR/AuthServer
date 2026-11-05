authserver tests

these are basically fake mc clients that do the login packets directly, no game needed
they all connect to 127.0.0.1:25565 so run the server locally first
need python + pip install cryptography

versions.py - ping + full login on 16 versions (1.7.10 to 1.21.10), each one connects from a diff 127.0.0.x so the rate limit doesnt get in the way
login1192.py token [759|760] - 1.19/1.19.2 login sending the verify token, this one works fine
login1192.py signature [759|760] - 1.19/1.19.2 login sending a random salt+signature with no chat key, this is the one that crashes the original
sig119.py - 1.19/1.19.2 with a real chat key: correct signature, wrong key, wrong token, no key
versions-new.py - same as versions.py but with 1.21.11 and 26.1/26.3
misc.py - maxPerPeer (4 conns same ip), garbage data, idle timeout (takes like 40s)

the fake player never actually logs in with mojang so "Authentication failed" is what u should get, means the whole handshake went through

versions.py sends the verify token on 1.19/1.19.2 so it passes even without the fix, use login1192.py signature to see the crash

fix-1.19.diff is the updated fix (git apply fix-1.19.diff). on 1.19-1.19.2 it reads the chat key from login start and checks the salt signature like vanilla does, instead of just skipping the check
results in results.txt

made by - ``Al green``