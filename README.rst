Cryptcrro
=================

``Cryptcrro`` is a python cryptographic library.

You can install it with::

       pip install cryptcrro

In this case, all modules are installed under the ``cryptcrro`` package.
   
``Cryptcrro`` includes both asymetric and symetric encryption, for encryption the protocols is asymetric ECIES + Chacha20 or RSA + Chacha20, for signing the protocols is ECDSA or RSA.

All Elliptic curve operation is done with the Secp256k1 curve.

``Cryptcrro`` also provide symmetric encryption protocols as:
       -AES-256_CTR

       -ChaCha20

       -Sha256_CTR*

*It is CTR encryption mode but using Sha256 instead of AES or other protocols. 

``Cryptcrro`` provide high level recipe through the ``crro`` module.

For example, symetric encryption can be done like that:

.. code-block:: pycon

    >>> from cryptcrro.symetric import crro 
    >>> plaintext = "Chancellor on brink of second bailout for banks"
    >>> key = scrro.generate_key()
    >>> ciphertext = scrro.encrypt(key, message)
    >>> decrypted_ciphertext = scrro.decrypt(key, ciphertext)

Or, asymetric encryption:

.. code-block:: pycon

    >>> from cryptcrro.asymetric import crro
    >>> private_key = crro.generate_private_key()
    >>> public_key = crro.generate_public_key(private_key)
    >>> plaintext = "Chancellor on brink of second bailout for banks"
    >>> ciphertext = crro.encrypt(public_key, message) 
    >>> decrypted_ciphertext = crro.decrypt(private_key, encrypted_message) 
