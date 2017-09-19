# Scoped Encryption Keys for Firefox Accounts

## Recommendations

### Sync key-sharing needs to be finer-grained

Before implementing key-sharing for Sync data, break the Sync keys up into
smaller pieces. I'm nervous about allowing external applications to learn the
master Sync key, because then a failure of the server-side ciphertext access
controls would leak the most critical user data (passwords), as would a
compromise/coercion of that server, or of the backend storage for Sync
ciphertext.

Does FxA store the FxA password in the Sync password store? If so, granting
read access to the Sync passwords is equivalent to granting access to the
entire account.

Passwords are special enough that the client should include some extra-scary
UX before authorizing sharing.

If I remember correctly, Sync already has per-collection keys, but they're
randomly generated, and stored in a bundle that is wrapped by the Sync master
key (and is that RSA keypair still involved?). Perhaps the Sync client can be
updated to derive collection-specific FxA scoped keys (with scopes like
"sync/history", "sync/bookmarks"), use these to wrap the existing random
per-collection keys, and store the wrapped records next to the ciphertext.
The same access controls that allow retrieval of e.g. bookmarks ciphertext
would also allow retrieval of the wrapped bookmarks key.

### Scope-to-HKDF Mapping is a new power

The FxA account server gets to map scope name to ``scoped_key_identifier``
(the HKDF derivation string). This expands the power of that server, because
the client has no way of knowing whether the derivation string is correct.

FxA keys (Sync in particular) is already reliant upon the
accounts.firefox.com login page being delivered correctly (the page which
accepts the user password, computes ``unwrapKey``, and receives ``wrapKb``).
However the current vulnerability is very specific: an attacker or coercer
would need to change the server to deliver a different static document.
Modifying the *API* server (which currently runs on a different host) could
cause the login process to fail, or a corrupted key to be delivered, but it
would not cause the user's password to be directly exposed (because the
password is stretched before being sent to the API server).

Adding a scope-to-identifier function to the API server gives that server
control over which apps can access which keys. The browser (or, rather, the
login page that runs in that browser) knows the OAuth application-id of the
page making the request, but it does not know what ``scoped_key_identifier``
should be used. The new API server could intentionally or accidentally map
multiple unrelated application-ids to the same scope-id, allowing one
application to learn the key of the other.

### The Scope-to-HKDF Server must be manged with care

The docs mention "an out-of-band mechanism to register which ``client_id``s
belong to which application".

Like with any OAuth2 Authorization Server, some human will be responsible for
managing registration requests from application authors who want to plug into
this system. These requests include the usual OAuth application data:
callback URL, a name, some description of what the service does, perhaps a
logo image.

This admin sits between the application and the eventual users. When a user
follows an OAuth login link, they'll be presented with an application name,
an icon, and a description of some scopes. Based upon just this information,
they'll be asked to make an authorization decision. The user is presented
with a *brand* (in the trademark sense), and they're mentally comparing what
they know about this brand (reputation) with what they want to accomplish
(description) and what authorities are being requested (risk). This is the
reason that OAuth2 registrations are generally not automated: it's too easy
to trick users when this is the only information they have to go on.

The admin decides what questions can be presented: users can reasonably
expect that someone has approved the application before they ever see it, so
they're effectively delegating some of their decision-making to the people
running the authorization server.

This admin is thus responsible for filtering out registration requests that
contain confusing names or misleading descriptions. If "Firefox Notes" is a
well-respected application, but "Firefax Notes" gets registered (with the
same icon), a user is likely to be tricked into granting the benefit of the
real application's reputation to the interloper. If the description makes
unrealistic claims about the application's features and benefits, the user
may risk giving it more access that it deserves (or really needs).

Likewise, if the authorization server can limit each application to some
pre-configured set of scopes, then this admin is applying some judgment as to
the appropriateness of those scopes. They're looking at the description and
the reputation of the author, and allowing that application to ask users for
those scopes.

The admin is implementing a function that maps (author reputation, displayed
application name, displayed description) to (allowed scopes), on behalf of
their users.

The Scoped Keys feature adds a new item to the output of this function: the
``scoped_key_identifier``. The admin needs to know about the kind of data
that other applications will store or expect to find in that particular
bucket, and they must decide whether the new application should be allowed
access to it. There may be other access mechanisms to inhibit access to
ciphertext, but these will depend upon the goodwill of some server, whereas
cryptographic protections have no such dependency. So the admin needs to
think carefully about user expectations.

If the key-identifier were exactly equal to the OAuth2 "client-id", then all
apps could only access their own data. But since the FxA server gets to
decide what this mapping is, the admin who adds each new OAuth2 application
must apply their judgement.

For the documented "lockbox" example, suppose the authors start up a new
related project (perhaps "lockbox-plus.com", on a non-mozilla domain), then
they'll need to convince the FxA admins that requests from an origin of
``lockbox-plus.com`` deserves access to the same data that the original app
was using. Admins must be in a position to evaluate these claims.

### app_origin checks are not meaningful in non-web applications

The "identity" of an application is fuzzy. For web-based applications, we use
the web origin (DNS zone) of the server from which the page was fetched. When
each application is registered, the ``redirect_uri`` is recorded, and the
OAuth2 "code" will only be delivered (via HTTP Redirect) to this one
location. The TLS/DNS-enforced mapping from the host portion of a URL to the
owner/operator of a web server is what turns the origin into an identity.

However for non-web applications (e.g. Android/iOS), this mapping is not
managed by DNS or the CA roots. Instead, each application can request control
over arbitrary URL schemes or subsets of HTTP URLs. The lack of centralized
(curated) mapping from scheme or domain to application is the source of the
"authorization code interception attack" that motivated RFC 7636's PKCE
protocol.

PKCE ensures that the application which requested an OAuth2 grant will be the
one that receives the resulting tokens. However it doesn't help bind the
mobile application to the scoped-key ``client_id`` or ``app_origin``.
Malicious Android/iOS apps can copy the ``client_id`` out of a legitimate
app, register the same local URL scheme (from ``redirect_uri``), then launch
a FxA login page that is identical to the "real" one. The resulting token and
key bundle might get returned to the malicious app instead of the legitimate
one, depending upon which app winds up first in the operating system's
dispatch table.

I'm not immediately aware of any mechanism that could fix this. While iOS
might hide the contents of an installed binary (are .ipa files encrypted?),
it is generally not recommended to rely upon this to hide secrets inside the
executable. The operating system would need to provide some kind of signed
attestation API, to allow each application to get a token signed by the OS,
and the OS can claim that the requesting application was signed by some
particular developer key.

Without a mechanism like this, I don't think it's safe to have mobile
applications share access to the same data as a web-based one.



### Key-ID derivation

The key-id is derived from the master key using a related derivation string.
The string is only two bytes different from the key string. While a correct
implementation of HKDF means these two keys will be independent, I worry
about application-level implementation errors, in particular a cut-and-paste
or tab-to-complete mistake that puts the same derivation string in both the
key and the keyid HKDF calls.

I'd suggest making the keyid derive from the scoped key, rather than having
both derive from the master `kB`. Any mistake is thus going to risk just the
scoped key, not the master key (and all other keys). Also, it's reasonable to
have the keyid use a truncated hash, since the only concern is collisions
with other keys for the same account and scope. Truncation is a backup
protection (only revealing 128 bits of a 256-bit key is nearly as good as not
revealing it at all), and having the keyid be visibly different than the key
itself seems like a good idea during debugging.

The scoped key is derived with:

```
kS = HKDF-SHA256(kB, size=32, salt=scoped_key_salt, context=
"identity.mozilla.com/picl/v1/scoped_key\n" +
scoped_key_identifier)
```

For the key-id, instead of the current:

```
kid =	strftime(scoped_key_timestamp, "YYYYMMDDHHMMSS") + "-" +
HKDF-SHA256(kB, size=32, salt=scoped_key_salt, context=
"identity.mozilla.com/picl/v1/scoped_kid\n" +
scoped_key_identifier)
```

perhaps it could be generated like this:

```
kid =	strftime(scoped_key_timestamp, "YYYYMMDDHHMMSS") + "-" +
HKDF-SHA256(kS, size=16, salt=scoped_key_salt, context=
"identity.mozilla.com/picl/v1/scoped_kid\n" +
scoped_key_identifier)
```


### Test Vectors should be added

For every example in the document, there should be fully-expanded examples of
inputs and outputs. Someone reading this document and implementing it should
be able to compare their code's results against the expected ones.
Ambiguities like where and when base64-encoding takes place (before input to
each hash function? before encryption?) can cause mututally-incompatible
implementations. Since scoped keys are meant to be used by 3rd-party code,
compatibility is even more important.

Consider putting non-ASCII names in these test vectors, where appropriate:

* Is the account name included anywhere?
* What happens when an internationalized domain name is used as an
  app-specific scope/origin?
  

### Limitations should be documented

The FxA key-management protocol was occasionally criticized because it was
implemented in web content, which allows a malicious/compromised/coerced
server to quietly replace the implementation for specific targetted users. It
makes it *possible* for the server to be honorable, but it doesn't *require*
such noble behavior.

This new scoped-keys protocol will probably receive similar criticism.
3rd-party applications which want to use end-to-end encryption of user data
must still deliver that application as a normal web page, making it
vulnerable to the same targetted-ignobility attack.

The documentation around this feature should clearly explain how this makes
things better. For example, it would protect user data against a
Heartbleed-style attack, which reveals the contents of server memory but
doesn't let the attacker change them.

Improving the story requires more involvement by the OS and the browser
upgrade machinery. For example, if FxA were implemented in browser chrome
instead of a web page (this was the plan, once upon a time), then the
attacker would have to compromise the Firefox upgrade pathway instead of
merely the accounts.firefox.com server. If the OS enforced code signatures on
application updates, they would have to compromise the signing process (steal
the private key, or substitute a modified application for signing). If
application signatures were published to a Certificate-Transparency -style
log, and the OS checked this, the attacker would risk their quietly-doctored
browser being exposed to the world. All of these approaches are out-of-scope
for a feature like Scoped Keys, but critics (who are correct in their
concern) should be encouraged to lend their energy towards the development of
improvements like those above.

### Managing Secrets in OAuth2 without using client_secret

This is related to the question of ``app_origin`` checks in non-web
applications. The Scoped Keys project seeks to manage secrets, but wants to
avoid depending upon the OAuth2 "secret mode", meaning that none of the
OAuth2 interactions are expected to use the ``client_secret`` field.

``client_secret`` exists to bind the access-token request (the POST that
includes the authorization code, the redirect_uri, and the
``client_id``/``client_secret``) to the target application (the party who
originally registered the application with the Authorization Server).

Without a ``client_secret``, anybody can turn a valid code into a valid
token, not just the backend server of the authorized application. To get a
valid code, an HTTP client that is not constrained by a browser (i.e.
``curl``) just does a GET

...


### scope=one+two or scope=one&scope=two ?

RFC6749 sections 3.3 and 4.1.1 indicate that scopes should be identified with
a space-delimited list of strings, which are then encoded as
``application/x-www-form-urlencoded``, meaning that each space is turned into
a plus symbol. The Scoped Keys docs are clear on this. However, web
programming doesn't generally include enough variable-type information to
distinguish between "a string which is a member of the pre-encoded list of
query arguments", "a string which has been x-www-form-urlencoded", and
potential unicode-laden variants of the same.

In particular, the built-in javascript ``escape()`` function will turn
``scope1 scope2+3`` into ``scope1%20scope2+3``, which some (marginal)
decoders might interpret as ``scope1 scope2`` (a single scope with an
embedded space) and ``3`` . The plus symbol isn't likely to be a big deal,
but the correctly encoded URL should contain ``scope2%2B3``.

So it'd be a good idea for the test vectors to include examples of multiple
scopes (in the same request), including scopes which include a plus symbol in
their name (which should appear as %2B). Ideally these scopes should include
non-ASCII symbols too. The vectors should show exactly what URLs are
generated, recognizing potential differences between a URL as submitted to
``window.location``, the bytes delivered in the first line of an HTTP
connection, and the string delivered to common web-server tools like Rails or
Node.js's ``express``.

### Side-channel attacks are fun

As the docs mention, the system might be vulnerable to side-channel attacks,
most notably a timing attack on the public-key encryption/decryption steps,
or token comparisons.

(insert analysis here)

## Bikeshedding

### Parameter names help programmers make fewer mistakes

``keys_jwk`` is the query argument to the signin URL, used to deliver the
public encryption key to the FxA login server. This parameter might benefit
from a name which indicates its function: it is providing the login server
with a target to which the requested keys can be delivered. Likewise
``derivedKeyBundle`` in the POST response (where the ``code`` is exchanged
for the OAuth2 token and the encrypted derived keys) could emphasize that
this is still protected by the public key.

## fxa-notes-example notes

* deriveECDSAESKey: since you're using HKDF everywhere else, use it here too,
  instead of a hand-implemented version of Concat KDF

## Future ideas

Splitting scopes into read-write and read-only is great. This could be
strengthened by having writes be public-key signed by a key that is only
available to writers. ...

The login process generates just one token, but multiple keys. The token is
"valid" for a number of scopes, but each key is only associated with a single
scope. There are scopes that do not get keys. It might be nice if these were
more unified. For example, each scope gets you a bundle that contains a
symmetric encryption key (for data), a signing key (to sign new versions of
mutable data ciphertext), a verifying key (to recognize those ciphertexts), a
write-access token (to submit with API calls that modify data), and a
read-access token (for API calls that read data). Read-only scopes would get
a subset of these keys/tokens. A cleverer scheme could compress these tokens
into a smaller number of values, by deriving less-powerful ones from the
more-powerful ones (e.g. the read-access token could be the hash of the
write-access token, which could be the hash of the signing key).
