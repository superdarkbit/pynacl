This is a fork of PyNaCl which attempts to provide BLAKE2b hash based key creation, message signatures, and signature verification. This is useful for Python projects related to the Nano cryptocurrency which uses keys and signing based on BLAKE2b (as well as Ed25519).

To install this library as a package to include in your code, run:

.. code-block:: console

    $ pip install pynacl

It make take several minutes to install. See INSTALL.rst for more information.

Example of code in use:

.. code-block:: python

    >>> from nacl.bindings import crypto_sign_ed25519_blake2b_seed_keypair, crypto_sign_ed25519_blake2b, crypto_sign_ed25519_blake2b_open
    >>> from binascii import unhexlify
    >>> pubkey, secretkey = crypto_sign_ed25519_blake2b_seed_keypair(unhexlify('0000000000000000000000000000000000000000000000000000000000000000'))
    (
        b'\x19\xd3\xd9\x19G]\xee\xd4ik]\x13\x01\x81Q\xd1\xaf\x88\xb2\xbd;\xcf\xf0H\xb4P1\xc1\xf3m\x18X', # '19d3d919475deed4696b5d13018151d1af88b2bd3bcff048b45031c1f36d1858'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\xd3\xd9\x19G]\xee\xd4ik]\x13\x01\x81Q\xd1\xaf\x88\xb2\xbd;\xcf\xf0H\xb4P1\xc1\xf3m\x18X' # '000000000000000000000000000000000000000000000000000000000000000019d3d919475deed4696b5d13018151d1af88b2bd3bcff048b45031c1f36d1858'
    )

    >>> msg = b'message'
    >>> sigmsg = crypto_sign_ed25519_blake2b(msg, secretkey)
    b'\x05\x91\x82\x94\xc6\x02\x8a\xb1\x9d\xba\x07x \xdd\n\xbf\r\xacXIc$\xc0i\xc8;\x7fR\xd9\x96Q\xb3\xa1\x01\xf5F[]\xdd\xd3\x03\x18\x18S\x9b\xb0\x102\x92\xc9$h"(\xe7\xf1H\xa7-=\x17ec\x02message' # '05918294c6028ab19dba077820dd0abf0dac58496324c069c83b7f52d99651b3a101f5465b5dddd3031818539bb0103292c924682228e7f148a72d3d176563026d657373616765'

    >>> msg == crypto_sign_ed25519_blake2b_open(sigmsg, pubkey)
    True
