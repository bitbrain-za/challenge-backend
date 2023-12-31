![MIT license](https://img.shields.io/github/license/bitbrain-za/challenge-backend)
[![dependency status](https://deps.rs/repo/github/bitbrain-za/challenge-backend/status.svg)](https://deps.rs/repo/github/bitbrain-za/challenge-backend)
[![Continuous integration](https://github.com/bitbrain-za/challenge-backend/actions/workflows/rust.yml/badge.svg)](https://github.com/bitbrain-za/challenge-backend/actions/workflows/rust.yml)

# Challenge Backend

Provides a backend interface to the DB.
Just has one endpoint to fetch the scores for a challenge

See api.json for more info. (api.yaml might also be up to date)

# Deploying

Install [Redis](https://redis.io/docs/install/install-redis/install-redis-on-linux/)

move (host) target/release/challenge_server to (target) /usr/bin/challenge_server
move (host) sysvinit/challenge_server to (target) /etc/init.d/challenge_server

`service start challenge_server`

install mysql and redis

# Configuring
Use `-S` to turn on TLS

Use `-p <PORT>` to set the port.

In the sysv script, you can set the port and security in the command

# logs

Logs can then be viewed here:
```
/var/log/challenge_server.log
/var/log/challenge_server.err
```
