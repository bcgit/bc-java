package org.bouncycastle.tls.crypto;

/**
 * Interface for message digest, or hash, services.
 */
public interface TlsHash
{
    /**
     * Update the hash with the passed in input.
     *
     * @param input input array containing the data.
     * @param inOff offset into the input array the input starts at.
     * @param length the length of the input data.
     */
    void update(byte[] input, int inOff, int length);

    /**
     * Return calculated hash for any input passed in.
     *
     * @return the hash value.
     */
    byte[] calculateHash();

    /**
     * Return a clone of this hash object representing its current state.
     *
     * @return a clone of the current hash.
     */
    Object clone();

    /**
     * Reset the hash underlying this service.
     */
    void reset();
}
