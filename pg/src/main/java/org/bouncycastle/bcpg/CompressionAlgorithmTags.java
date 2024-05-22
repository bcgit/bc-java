package org.bouncycastle.bcpg;

/**
 * Basic tags for compression algorithms.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4880.html#section-9.3">
 *     RFC4880 - Compression Algorithms</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-compression-algorithms">
 *     LibrePGP - Compression Algorithms</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-compression-algorithms">
 *     Crypto-Refresh - Compression Algorithms</a>
 */
public interface CompressionAlgorithmTags
{
    /** No compression. */
    int UNCOMPRESSED = 0;

    /** ZIP (RFC 1951) compression. Unwrapped DEFLATE. */
    int ZIP = 1;

    /** ZLIB (RFC 1950) compression. DEFLATE with a wrapper for better error detection. */
    int ZLIB = 2;

    /** BZIP2 compression. Better compression than ZIP but much slower to compress and decompress. */
    int BZIP2 = 3;
}
