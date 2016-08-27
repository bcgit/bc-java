package org.bouncycastle.tls.crypto;

import java.security.SecureRandom;

/**
 * Generic interface for objects generating random bytes.
 */
public interface NonceRandomGenerator
{
    /**
     * Add more seed material to the generator.
     *
     * @param seed a byte array to be mixed into the generator's state.
     */
    void addSeedMaterial(byte[] seed);

    /**
     * Add more seed material to the generator.
     *
     * @param seed a long value to be mixed into the generator's state.
     */
    void addSeedMaterial(long seed);

    /**
     * Add more seed material to the generator.
     *
     * @param seedSource a source of entropy to be mixed into the generators's state.
     */
    void addSeedMaterial(SecureRandom seedSource);

    /**
     * Fill bytes with random values.
     *
     * @param bytes byte array to be filled.
     */
    void nextBytes(byte[] bytes);

    /**
     * Fill part of bytes with random values.
     *
     * @param bytes byte array to be filled.
     * @param start index to start filling at.
     * @param len length of segment to fill.
     */
    void nextBytes(byte[] bytes, int start, int len);

}
