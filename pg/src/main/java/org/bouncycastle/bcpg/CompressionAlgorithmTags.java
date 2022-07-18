package org.bouncycastle.bcpg;

/**
 * Basic tags for compression algorithms
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
