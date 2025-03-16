Cryptcrro
=================

``Cryptcrro`` is a python cryptographc library.

   You can install it with::

       pip install cryptcrro

   In this case, all modules are installed under the ``cryptcrro`` package.

``Cryptcrro`` includes both asymetric and symetric encryption, for encryption the protocols is asymetric ECIES + AES-128 or RSA + AES-128, for signing the protocols is ECDSA or RSA.

All Elliptic curve operation is done with the Secp256k1 curve.

``Cryptcrro`` also provide a symmetric encryption called sha256_CTR, it is basically a AES-CTR encryption mode but using Sha256 instead of AES. (I know it seems weird, but if you are perplexed about encryption with a hashing function pls check the code).


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
