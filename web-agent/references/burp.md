# Burp Suite with web-agent

Use Burp's local HTTP proxy listener to see agent requests in **Proxy > HTTP
history**. The examples assume a listener at `127.0.0.1:8080`; check Burp's
Proxy settings for the actual address and port. Turn Intercept off when requests
should pass through without waiting. Keep the listener on loopback.

After initializing the authorized web-agent session, send one request through
Burp with:

```text
python3 <skill>/assets/request.py --workspace <workspace> \
  --url <manifest-start-url> --proxy http://127.0.0.1:8080
```

For an HTTPS lab target with an untrusted certificate, add `--insecure-tls`
only for that request. The proxy must use HTTP and a loopback address with an
explicit port. The target URL still must match the manifest's exact origin.
The proxy flag changes the transport; it does not expand the authorized target.

To pass a Burp-captured request to the agent, select it in **Proxy > HTTP
history**, copy the complete raw request including its request line, headers,
blank line, and body, and save it beneath the session workspace, for example
`<workspace>/web/requests/ucp-login.burp.txt`. Check that its Host, path, body,
and cookies are the intended ones before sending. Then run:

```text
python3 <skill>/assets/request.py --workspace <workspace> \
  --burp-request-file <workspace>/web/requests/ucp-login.burp.txt \
  --proxy http://127.0.0.1:8080 --insecure-tls
```

The raw request file is read only from the session workspace. The request URL
and Host must match the manifest's exact origin. The helper rejects malformed
headers, transfer encoding, and a body on GET or HEAD; it calculates a fresh
Content-Length from the saved body. Keep raw requests, prepared evidence, and
cookie state private because they may contain session credentials. A saved
request is replayed once per command through the normal attempt ledger; inspect
the response and coverage before trying a changed request.

For a browser using Burp, set its proxy to the same local listener and install
Burp's CA certificate in that browser for HTTPS interception. Burp's built-in
browser already uses the configured proxy. Browser history can then supply the
raw request file used above.
