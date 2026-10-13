# url-signer

Stateless, tamper-evident signed URLs for PHP. HMAC-SHA256 over a canonicalised
query string, with an expiry claim. No database, no session, no shared state
beyond a single secret.

Useful for time-limited download links, unsubscribe links, password-reset links,
and any other "give the client a URL they can't modify" case.

## Install

Copy `src/UrlSigner.php` into your project, or `composer require cgalileo/url-signer`.

## Example

```php
use UrlSigner\UrlSigner;

$signer = new UrlSigner(getenv('URL_SIGNING_SECRET'));

// produce a link valid for 10 minutes
$url = $signer->sign('https://example.test/download', ['file' => 'report.pdf'], 600);

// later, on the receiving endpoint:
if (!$signer->verify($_SERVER['REQUEST_URI'])) {
    http_response_code(403);
    exit('Invalid or expired link.');
}
```

## How it works

1. Query parameters are sorted by key and URL-encoded canonically.
2. An `exp` claim (unix timestamp) is appended.
3. An HMAC-SHA256 of the canonical string is computed with the secret and
   appended as `sig`.
4. `verify()` recomputes the HMAC over everything except `sig`, compares it in
   constant time with `hash_equals()`, and checks `exp` against the current time.

Because verification is a pure function of the URL and the secret, any node
holding the secret can verify without coordination. Rotate the secret by
accepting two secrets during a grace window (see `verifyWithKeys()`).

## Security notes

- The secret must be at least 32 bytes of CSPRNG output. Do not commit it.
- Signatures are compared with `hash_equals()` to avoid timing leaks.
- This signs URLs; it does not encrypt them. Do not place secrets in the query
  string you sign.

## License

MIT.
