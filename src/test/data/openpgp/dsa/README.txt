This archive contains material to help verify interoperability to the
OpenPGP DSA2 design as implemented in GnuPG.

Keys are located in the keys directory.  Included are:

 1024 bits, 160 bit q size (i.e. regular old DSA)
 2048 bits, 224 bit q size
 3072 bits, 256 bit q size
 7680 bits, 384 bit q size
15360 bits, 512 bit q size

All secret keys have the passphrase "test".

Note the inclusion of 7680/384 and 15360/512 keys.  They're large,
inconvenient and absurdly slow.  GnuPG will accept any size key, but
will not generate DSA keys over 3072 bits.  I include these keys
mainly for be-liberal-in-what-you-accept testing.

There are are signatures issued by these keys in the sigs directory.
The filenames indicate the key used to make the signature, and the
number of bits of the hash.  In the case of the 1024-bit DSA key
(160-bit q size), there are 5 signatures using different hashes.  This
is to demonstrate hash truncation to fit in the 160-bit hash size of
that key.

File			Key size    Hash
----------------------  ----------  -------
dsa-1024-160-sign.gpg	 1024 bits  SHA-1
dsa-1024-224-sign.gpg	 1024 bits  SHA-224 (truncated to 160 bits)
dsa-1024-256-sign.gpg	 1024 bits  SHA-256 (truncated to 160 bits)
dsa-1024-384-sign.gpg	 1024 bits  SHA-384 (truncated to 160 bits)
dsa-1024-512-sign.gpg	 1024 bits  SHA-512 (truncated to 160 bits)
dsa-2048-224-sign.gpg	 2048 bits  SHA-224
dsa-3072-256-sign.gpg	 3072 bits  SHA-256
dsa-7680-384-sign.gpg	 7680 bits  SHA-384
dsa-15360-512-sign.gpg	15360 bits  SHA-512
