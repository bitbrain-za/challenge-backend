# Challenge Backend

Provides a backend interface to the DB.
Just has one endpoint to fetch the scores for a challenge

See api.yaml for more info.

# Deploying

move (host) target/release/challenge_server to (target) /usr/bin/challenge_server
move (host) sysvinit/challenge_server to (target) /etc/init.d/challenge_server

`service start challenge_server`

# Configuring
Use `-P 1234` to set the port to 1234
In the sysv script, you can set the port in the command

# logs

Logs can then be viewed here:
```
/var/log/challenge_server.log
/var/log/challenge_server.err
```
