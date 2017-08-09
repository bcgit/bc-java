package org.bouncycastle.tls.crypto.impl;

/**
 * Base interface for a generic TLS MAC implementation for use with a cipher suite.
 */
public interface TlsSuiteMac
{
    /**
     * Return the output length (in bytes) of this MAC.
     *
     * @return The output length of this MAC.
     */
    int getSize();

    /**
     * Calculate the MAC for some given data.
     *
     * @param type    The message type of the message.
     * @param message A byte array containing the message.
     * @param offset  The number of bytes to skip, before the message starts.
     * @param length  The length of the message.
     * @return A new byte array containing the MAC value.
     */
    byte[] calculateMac(long seqNo, short type, byte[] message, int offset, int length);

    /**
     * Constant time calculation of the MAC for some given data with a given expected length.
     *
     * @param seqNo The sequence number of the cipher text.
     * @param type The content type of the message.
     * @param message A byte array containing the message.
     * @param offset The number of bytes to skip, before the message starts.
     * @param length The length of the message.
     * @param expectedLength The expected length of the full message,
     * @param randomData Random data for padding out the MAC calculation if required.
     * @return A new byte array containing the MAC value.
     */
    byte[] calculateMacConstantTime(long seqNo, short type, byte[] message, int offset, int length, int expectedLength, byte[] randomData);
}
