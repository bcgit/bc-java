package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

/**
 * Splits each request of exactly splitLength bytes into 4-byte requests to the generator it wraps, passing every other
 * request through unchanged.
 * <p>
 * NTRU Prime draws a polynomial's p random 32-bit words in one call of 4p bytes, where the reference implementation
 * that generated the KATs draws each word by its own 4-byte call. NISTSecureRandom discards the rest of its last block
 * on every call, so the two give different bytes; wrapping it with splitLength = 4p reproduces the reference's calls.
 * No other request NTRU Prime makes is 4p bytes long.
 */
class ReferenceDrawsRandom
    extends SecureRandom
{
    private final SecureRandom random;
    private final int splitLength;

    ReferenceDrawsRandom(SecureRandom random, int splitLength)
    {
        this.random = random;
        this.splitLength = splitLength;
    }

    public void nextBytes(byte[] bytes)
    {
        if (bytes.length != splitLength)
        {
            random.nextBytes(bytes);
            return;
        }

        byte[] word = new byte[4];
        for (int i = 0; i < bytes.length; i += 4)
        {
            random.nextBytes(word);
            System.arraycopy(word, 0, bytes, i, 4);
        }
    }
}
