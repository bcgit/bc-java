package org.bouncycastle.bcpg;

/**
 * Basic tags for symmetric key algorithms.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4880.html#section-9.2">
 *     RFC4880 - Symmetric-Key Algorithms</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-symmetric-key-algorithms">
 *     LibrePGP - Symmetric-Key Algorithms</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-symmetric-key-algorithms">
 *     Crypto-Refresh - Symmetric-Key Algorithms</a>
 */
public interface SymmetricKeyAlgorithmTags 
{
    /**
     * Plaintext or unencrypted data.
     */
    int NULL = 0;
    /**
     * IDEA.
     */
    int IDEA = 1;
    /**
     * Triple-DES (DES-EDE, as per spec - 168-bit key derived from 192).
     */
    int TRIPLE_DES = 2;
    /**
     * CAST5 (128-bit key, as per RFC 2144).
     */
    int CAST5 = 3;
    /**
     * Blowfish (128-bit key, 16 rounds).
     */
    int BLOWFISH = 4;
    /**
     * Reserved for SAFER-SK128 (13 rounds).
     */
    int SAFER = 5;
    /**
     * Reserved for DES/SK.
     */
    int DES = 6;
    /**
     * AES with 128-bit key.
     */
    int AES_128 = 7;
    /**
     * AES with 192-bit key.
     */
    int AES_192 = 8;
    /**
     * AES with 256-bit key.
     */
    int AES_256 = 9;
    /**
     * Twofish with 256-bit key.
     */
    int TWOFISH = 10;
    /**
     * Camellia with 128-bit key.
     */
    int CAMELLIA_128 = 11;
    /**
     * Camellia with 192-bit key.
     */
    int CAMELLIA_192 = 12;
    /**
     * Camellia with 256-bit key.
     */
    int CAMELLIA_256 = 13;

    // 100 to 110: Private/Experimental algorithms

    // 253, 254, 255 reserved to avoid collision with secret key encryption
}
