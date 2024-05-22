package org.bouncycastle.bcpg;

/**
 * Basic tags for hash algorithms.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4880.html#section-9.4">
 *     RFC4880 - Hash Algorithms</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-hash-algorithms">
 *     LibrePGP - Hash Algorithms</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-hash-algorithms">
 *     Crypto-Refresh - Hash Algorithms</a>
 */
public interface HashAlgorithmTags 
{
    /**
     * MD5.
     * Implementations MUST NOT use this to generate signatures.
     * Implementations MUST NOT use this as a hash function in ECDH KDFs.
     * Implementations MUST NOT generate packets with this hash function in an S2K KDF.
     * Implementations MUST NOT use this hash function in an S2K KDF to decrypt v6+ packets.
     */
    int MD5 = 1;
    /**
     * SHA-1.
     * Implementations MUST NOT use this to generate signatures.
     * Implementations MUST NOT use this as a hash function in ECDH KDFs.
     * Implementations MUST NOT generate packets with this hash function in an S2K KDF.
     * Implementations MUST NOT use this hash function in an S2K KDF to decrypt v6+ packets.
     */
    int SHA1 = 2;
    /**
     * RIPEMD-160.
     * Implementations MUST NOT use this to generate signatures.
     * Implementations MUST NOT use this as a hash function in ECDH KDFs.
     * Implementations MUST NOT generate packets with this hash function in an S2K KDF.
     * Implementations MUST NOT use this hash function in an S2K KDF to decrypt v6+ packets.
     */
    int RIPEMD160 = 3;
    /**
     * Reserved for double-width SHA (experimental).
     */
    int DOUBLE_SHA = 4;
    /**
     * Reserved for MD2.
     */
    int MD2 = 5;
    /**
     * Reserved for TIGER/192.
     */
    int TIGER_192 = 6;
    /**
     * Reserved for HAVAL (5 pass, 160-bit).
     */
    int HAVAL_5_160 = 7;
    /**
     * SHA2-256.
     * Compliant implementations MUST implement.
     */
    int SHA256 = 8;
    /**
     * SHA2-384.
     */
    int SHA384 = 9;
    /**
     * SHA2-512.
     */
    int SHA512 = 10;
    /**
     * SHA2-224.
     */
    int SHA224 = 11;
    /**
     * SHA3-256.
     */
    int SHA3_256 = 12;
    /**
     * SHA3-512.
     */
    int SHA3_512 = 14;

    /**
     * Reserved for MD4.
     * @deprecated non-standard
     */
    int MD4 = 301;
    /**
     * Reserved for SHA3-224.
     * @deprecated non-standard
     */
    int SHA3_224 = 312;
    /**
     * Reserved for SHA3-256.
     * @deprecated non-standard
     */
    int SHA3_256_OLD = 313;
    /**
     * Reserved for SHA3-384.
     * @deprecated non-standard
     */
    int SHA3_384 = 314;
    /**
     * Reserved for SHA3-512.
     * @deprecated non-standard
     */
    int SHA3_512_OLD = 315;

    /**
     * Reserved for SM3.
     * @deprecated non-standard
     */
    int SM3 = 326;

}
