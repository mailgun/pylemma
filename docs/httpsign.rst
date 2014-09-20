********
httpsign
********

Mailgun tools for signing and authenticating HTTP requests between web services.

**Overview**

An keyed-hash message authentication code (HMAC) is used to provide integrity and
authenticity of a message between web services. The following elements are input
into the HMAC. Only the items in bold are required to be passed in by the user, the
other elements are either optional or build by pylemma for you.

* **Shared secret**, a randomly generated number from a CSPRNG.
* Timestamp in epoch time (number of seconds since January 1, 1970 UTC).
* Nonce, a randomly generated number from a CSPRNG.
* **Request body.**
* Optionally the HTTP Verb and HTTP Request URI.
* Optionally an additional headers to sign.

Each request element is delimited with the character `|` and each request element is
preceded by it's length. A simple example with only the required parameters:

.. code-block:: py

   shared_secret = '042DAD12E0BE4625AC0B2C3F7172DBA8'
   timestamp     = '1330837567'
   nonce         = '000102030405060708090a0b0c0d0e0f'
   request_body  = '{"hello": "world"}'

   signature     = HMAC('042DAD12E0BE4625AC0B2C3F7172DBA8',
      '10|1330837567|32|000102030405060708090a0b0c0d0e0f|18|{"hello": "world"}')

The timestamp, nonce, signature, and signature version are set as headers for the
HTTP request to be signed. They are then verified on receiving side by running the
same algorithm and verifying that the signatures match.

Note: By default the service can securely handle authenticating 5,000 requests per
second. If you need to authenticate more, increase the capacity of the nonce 
cache when initializing the package.

**Examples**

*Signing a Request*

.. code-block:: py

   import lemma
   import requests

   lemma.initialize('/path/to/key.file')

   [...]
   
   # sign request
   request_body = '{"hello": "world"}'
   timestamp, nonce, signature, signature_version = \
      lemma.sign_request(request_body)

   # build and submit request
   request_headers = {
      'Content-type': 'application/json',
      'X-Mailgun-Timestamp': timestamp,
      'X-Mailgun-Nonce': nonce,
      'X-Mailgun-Signature': signature,
      'X-Mailgun-Signature-Version': signature_version}
    requests.post(url, headers=request_headers, data=request_body)

*Signing a Request with Headers*

.. code-block:: py

   import lemma
   import requests

   lemma.initialize('/path/to/key.file')

   [...]
   
   # sign request
   request_body = '{"hello": "world"}'
   timestamp, nonce, signature, signature_version = \
      lemma.sign_request(request_body, headers={'X-Mailgun-Header': 'foobar'})

   # build and submit request
   request_headers = {
      'Content-type': 'application/json',
      'X-Mailgun-Header': 'foobar'
      'X-Mailgun-Timestamp': timestamp,
      'X-Mailgun-Nonce': nonce,
      'X-Mailgun-Signature': signature,
      'X-Mailgun-Signature-Version': signature_version}
    requests.post(url, headers=request_headers, data=request_body)

*Signing a Request with HTTP Verb and URI*

.. code-block:: py

   import lemma
   import requests

   lemma.initialize('/path/to/key.file')

   [...]
   
   # sign request
   request_body = '{"hello": "world"}'
   timestamp, nonce, signature, signature_version = \
      lemma.sign_request(request_body,
      http_verb='GET', http_request_uri='/path?key=value#fragment')

   # build and submit request
   request_headers = {
      'Content-type': 'application/json',
      'X-Mailgun-Timestamp': timestamp,
      'X-Mailgun-Nonce': nonce,
      'X-Mailgun-Signature': signature,
      'X-Mailgun-Signature-Version': signature_version}
    requests.post(url, headers=request_headers, data=request_body)

*Authenticating a Request*

.. code-block:: py

   from flask import Flask
   from flask import request
   import lemma

   [...]

   @app.route("/", methods=['POST'])
   def process_webhook():

      # extract headers and body
      timestamp = request.headers.get('X-Mailgun-Timestamp', '')
      nonce = request.headers.get('X-Mailgun-Nonce', '')
      signature = request.headers.get('X-Mailgun-Signature', '')
      request_body = request.data

      if not lemma.authenticate_request(timestamp, nonce, request_body, signature):
         return 'Invalid request.'

      return 'Valid request.'

