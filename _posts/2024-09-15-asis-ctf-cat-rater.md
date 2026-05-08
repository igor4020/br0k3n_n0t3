---
title: "ASIS CTF 2024 Quals — Cat Rater — Web Writeup"
date: 2024-09-15 21:00:00 -0300
read_time: 8
tags: [ctf, web, writeup, ssrf, redis]
excerpt: "A web challenge from ASIS CTF 2024 Quals. SSRF into Redis through curl, with a regex that blocks spaces, dashes, and percent signs — solved with dict:// + EVAL + RANDOMKEY."
---

> Played for **SeaDragons** (Universidade Federal do Ceará). Originally on [Medium](https://medium.com/@igormelo4020/asis-ctf-2024-quals-cat-reader-web-writeup-95d87df627db).

## The challenge

The challenge gives us source for the application and a description that says it's a website that rates how cute cats are.

![Challenge prompt: Cat Rater — My new startup is about a website that rates how cute cats are]({{ '/assets/images/cat-rater/challenge-prompt.png' | relative_url }})

The provided files:

![Files provided in VS Code: chall/main.py, Dockerfile, docker-compose.yml]({{ '/assets/images/cat-rater/vscode-files.png' | relative_url }})

I'll show the solution from the local environment since it's exactly the same as the remote one. Spinning up the containers gives us a `chall` web service and a `redis` database.

![docker-compose up --build output]({{ '/assets/images/cat-rater/docker-compose-up.png' | relative_url }})

After `docker compose up --build` we land on the site at port 8080: a single form that takes a URL, fetches it, and rates your cat.

![Cat Rater UI: Enter a link to your cat picture]({{ '/assets/images/cat-rater/initial-ui.png' | relative_url }})

Submitting `https://google.com` gets you back **"Your cat got 2/10"**. Well — it seems my cat is ugly.

![Your cat got 2/10]({{ '/assets/images/cat-rater/cat-2of10.png' | relative_url }})

## The source

```python
from flask import Flask, render_template, session, request, redirect
import subprocess
import secrets
import random
import redis
import uuid
import os
import re

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)
flag = os.environ.get('FLAG', 'ASIS{test-flag}')
rds = redis.Redis(host='redis', port=6379)
uuidReg = re.compile(r'^[\da-f]{8}-([\da-f]{4}-){3}[\da-f]{12}$')

@app.route('/')
def index():
    print(request.get('get'))
    return render_template('main.html')

@app.route('/rate', methods=['POST'])
def rate():
    link = request.form.get('link')
    print(link)
    if not link or re.search(r'[\x00-\x20\\[\]\"-]', link):
        return 'Invalid link', 400, {'Content-Type': 'text/plain'}
    try:
        p = subprocess.run(["/usr/bin/curl", link], capture_output=True)
        print(p)
        print(p.returncode)
        if p.returncode == 0:
            resultID = str(uuid.uuid4())
            rds.set(resultID, str(random.randint(1, 9)))
            return redirect(f'/result?id={resultID}')
    except Exception as e:
        print(e)
    return 'Something bad happened', 500, {'Content-Type': 'text/plain'}

@app.route('/result')
def result():
    rid = request.args.get('id')
    if not rid:
        return 'Result ID is missing', 400, {'Content-Type': 'text/plain'}
    if not uuidReg.match(rid):
        return 'Invalid ID', 400, {'Content-Type': 'text/plain'}
    result = rds.get(rid)
    if not result:
        return 'Result not found', 400, {'Content-Type': 'text/plain'}
    if result == 10:
        return render_template('result.html', msg=flag)
    else:
        return render_template('result.html', msg=f'Your cat got {result}/10')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
```

## Going through the code

- Three routes: `/`, `/rate`, `/result`.
- The flag is loaded from an env variable.
- A regex enforces UUID-shaped IDs.
- The two interesting functions are `rate` and `result`.

### `rate`

- Reads the user input into `link`.
- Checks it isn't empty and runs the regex `[\x00-\x20\\[\]\"-]` over it (rejects control chars, spaces, backslash, brackets, quotes, and `-`).
- Calls `curl` on the link via `subprocess.run` with `shell=False` — so it's an SSRF, **not** command injection (we spent a while trying that one — `:P`).
- If curl exits 0, it stores `randint(1,9)` under a fresh UUID key in Redis and redirects to `/result?id=...`.

### `result`

- Reads `id` from the query string.
- Validates it's non-empty and matches the UUID regex.
- Gets the value from Redis. If the value is `10`, render the flag; otherwise render the rating.

## The plan

We need to set the value for our key in Redis to `10`. We have an SSRF, but no way to talk to Redis directly from HTTP, and the regex blocks a lot of useful characters.

Constraints:

- The `/result` route only accepts UUID-shaped keys.
- We have to get to Redis somehow through curl.

A bit of googling lands you on **SSRF + Redis** material — including [this Hacktricks page](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis). Since the services live on the same docker-compose network, the web service can reach Redis at `redis:6379`.

A first naive attempt — point curl directly at the Redis port:

![Cat Rater form with http://redis:6379/test in the input]({{ '/assets/images/cat-rater/ssrf-attempt.png' | relative_url }})

The `/rate` handler comes back with the generic error page (curl exits non-zero):

![/rate returning 'Something bad happened']({{ '/assets/images/cat-rater/something-bad-happened.png' | relative_url }})

The classic next trick is to use the `gopher://` protocol via curl to send raw bytes to Redis. We tried that and the logs surfaced this:

![Redis log: 'Possible SECURITY ATTACK detected... Cross Protocol Scripting']({{ '/assets/images/cat-rater/redis-security-attack.png' | relative_url }})

Looks like newer Redis builds detect and reject the gopher cross-protocol injection. We need to circumvent it.

A read through `man curl` shows curl supports a *lot* of protocols — DICT, FILE, FTP, FTPS, GOPHER, GOPHERS, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, MQTT, POP3, POP3S, RTMP, RTMPS, RTSP, SCP, SFTP, SMB, SMBS, SMTP, SMTPS, TELNET, TFTP, WS, WSS. None of those are blocked by the regex.

![curl(1) man page synopsis]({{ '/assets/images/cat-rater/curl-manual.png' | relative_url }})

Poking with gopher first — the literal `keys` command trips Redis's protocol heuristic, but a misspelled command (`xkeys`) goes straight through and the cross-protocol scripting check still trips on whatever it does match — neither route gets us a clean ack:

![gopher://redis:6379/keys vs xkeys responses]({{ '/assets/images/cat-rater/gopher-keys.png' | relative_url }})

After some experimentation I landed on **`dict://`**.

## The other regex problem

We can talk to Redis through `dict://`. But the regex still kicks in:

```
re.search(r'[\x00-\x20\\[\]\"-]', link)
```

That `\x00-\x20` range covers control characters **and the space** (`\x20`). It also blocks `\`, `[`, `]`, `"`, and `-`. Crucially: **`%` is not blocked, but space *is*** — and from the Hacktricks SSRF tricks I learned that URL-encoding helps with gopher, but here `%` isn't blocked while space is. That sounds backwards, but the catch is that Redis commands separate arguments with spaces. Without spaces, you can only run single-word commands (like `FLUSHALL`, `RANDOMKEY`), and those don't help us set a UUID key to 10.

You should read the RFC for these protocols — they're old and quirky. `dict://` uses `:` as its query separator. So `dict://redis:6379/keys:*` sends `keys *` as the command without ever using a literal space:

```
dict://redis:6379/keys:*
```

That works — keys come back (the `-ERR unknown subcommand 'libcurl'` is just the libcurl banner exchange; the keys themselves print after):

![dict:// curl returning Redis keys]({{ '/assets/images/cat-rater/dict-keys.png' | relative_url }})

Now the question becomes: how do we run a *multi-arg* Redis command without spaces?

Eventually I remembered Redis's `EVAL`. It takes a Lua script string, and inside Lua we can use `redis.call(...)` to chain commands together. The `dict://` separator lets us pass the script as a single colon-delimited token, no spaces needed:

```
dict://redis:6379/eval:"redis.call('SET',redis.call('RANDOMKEY'),'10')":0
```

`redis.call('SET', redis.call('RANDOMKEY'), '10')` sets a *random existing key* to `10` — and we don't need to reference it by name (which would require `-`s in the UUID anyway, blocked by the regex).

But there's a snag: when we paste this through the shell directly, the quotes get mangled and Redis answers with `Protocol error: unbalanced quotes in request`:

![dict:// eval returning 'unbalanced quotes in request']({{ '/assets/images/cat-rater/eval-unbalanced-quotes.png' | relative_url }})

**Good news** — `subprocess.run` is called with `shell=False`, so curl receives the URL as a single argv entry. The quotes survive intact through the SSRF that wouldn't survive a shell. Submitting the same payload through the form makes the eval actually run on the chall side:

![Submitting the dict:// eval payload through the Cat Rater form]({{ '/assets/images/cat-rater/dict-eval-ui.png' | relative_url }})

![chall logs: eval call returns OK on the redis side]({{ '/assets/images/cat-rater/eval-via-curl.png' | relative_url }})

## The exploit

There's still one issue. With many people solving the challenge, `RANDOMKEY` could land on someone else's UUID. We need to clear the database before our rating gets stored, so there's exactly one key when we set the `10`.

`FLUSHALL` is single-word and doesn't need spaces or anything blocked by the regex. Perfect.

### Step by step

**1.** First request: clear Redis.

```
dict://redis:6379/flushall
```

![chall logs: dict:// flushall returns OK and redis writes 'DB saved on disk']({{ '/assets/images/cat-rater/flushall.png' | relative_url }})

The `/rate` handler then inserts our own key with a random rating between 1 and 9. Now Redis contains exactly one key — ours. We get redirected to `/result?id=<uuid>` — note that UUID, e.g. `96a2c4be-330d-4177-927d-f825f19ef1b5`.

**2.** Second request: set the only existing key to 10.

```
dict://redis:6379/eval:"redis.call('SET',redis.call('RANDOMKEY'),'10')":0
```

![chall logs: dict:// eval SET RANDOMKEY '10' executed]({{ '/assets/images/cat-rater/eval-set-10.png' | relative_url }})

The `/rate` handler runs curl, which talks to Redis via `dict://`. The Lua script picks `RANDOMKEY` (our key, since it's the only one in the DB at the moment) and sets its value to `10`. Then `/rate` adds *another* key with a 1–9 rating, but the order matters: ours was set first, and we already have its UUID.

**3.** Visit `/result?id=96a2c4be-330d-4177-927d-f825f19ef1b5`.

![Result page with the flag]({{ '/assets/images/cat-rater/flag-result.png' | relative_url }})

Flag.

## Closing thoughts

This was a fun challenge — easiest of the web set in the CTF, but it forced us through a long chain of small realizations: SSRF → gopher (blocked) → curl protocol survey → `dict://` → space-less Redis commands → `EVAL` + `RANDOMKEY` + `FLUSHALL` to get one key in the database we could indirectly target.

Stuff I'd remember for next time:

- When `gopher://` is blocked, there are *many* other curl protocols. `dict://` and `ldap://` are the next ones I'd reach for.
- `subprocess.run([...], shell=False)` blocks command injection — but the *content* of an argv entry can still carry SSRF payloads with full-fidelity quoting.
- Redis Lua scripting (`EVAL` + `redis.call`) is a beautiful one-shot when your transport can't carry argument separators.

Hope you learned from this like we did. **Keep hacking!**
