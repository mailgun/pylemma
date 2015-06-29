secret
======

Mailgun tools for authenticated encryption.

**Overview**

Package secret provides tools for encrypting and decrypting
authenticated messages. Like all lemma packages, metrics are built in
and can be emitted to check for anomalous behavior.

**Examples**

*Key generation and use*

.. code:: python

    from lemma import secret

    # generate a new randomly generated key. use this to create a new key.
    key_bytes = secret.new_key()

    // read base64 encoded key in from disk
    secret.initialize('/path/to/secret.key')

    # set key bytes directly
    secret.initialize_with_key('\x00'*32)
 
    # given a base64 encoded key, return key bytes
    b = secret.encodedstring_to_bytes("c3VycHJpc2UsIHRoaXMgaXMgYSBmYWtlIGtleSE=")

    # given key bytes, return an base64 encoded key
    eb = secret.bytes_to_encodedstring('\x00'*24)

--------------

*Encrypt message with existing key*

.. code:: python

    from lemma import secret

    # create a new secret encryption service using the above generated key
    secret.initialize('/path/to/secret.key')

    # seal message
    ciphertext_bytes, nonce_bytes = secret.seal('hello, box!')
    
    # optionally base64 encode them and store them somewhere (like in a database)
    ciphertext = secret.bytes_to_encodedstring(ciphertext_bytes)
    nonce = secret.bytes_to_encodedstring(nonce_bytes)
    print 'ciphertext: {}, nonce: {}'.format(ciphertext, nonce)

--------------

*Encrypt message with passed in key*

.. code:: python

    from lemma import secret

    # create a new secret encryption service with a junk key
    secret.initialize_with_key('\x00'*32)

    # seal message
    ciphertext_bytes, nonce_bytes = secret.seal('hello, box!', key='\x01'*32)

    # optionally base64 encode them and store them somewhere (like in a database)
    ciphertext = secret.bytes_to_encodedstring(ciphertext_bytes)
    nonce = secret.bytes_to_encodedstring(nonce_bytes)
    print 'ciphertext: {}, nonce: {}'.format(ciphertext, nonce)

--------------

*Decrypt message*

.. code:: python

    from lemma import secret

    # create a new secret encryption service using the above generated key
    secret.initialize('/path/to/secret.key')

    # read in ciphertext and nonce
    ciphertext_bytes = [...]
    nonce_bytes = [...]
    
    # decrypt and open message
    plaintext = secret.open(ciphertext_bytes, nonce_bytes)
    
    print 'plaintext: {}'.format(plaintext)

--------------

*Emit Metrics*

.. code:: python

    from lemma import metrics
    from lemma import secret

    # create a new secret encryption service using the above generated key
    secret.initialize('/path/to/secret.key')

    # define statsd server for metrics
    metrics.initialize('www.example.com', 8125, 'a_secret_prefix')
    
    # now, when using the service, success and failures will be emitted to statsd
    plaintext = secret.open(ciphertext_bytes, nonce_bytes)
