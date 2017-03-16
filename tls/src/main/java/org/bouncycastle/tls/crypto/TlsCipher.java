package org.bouncycastle.tls.crypto;

import java.io.IOException;

/**
 * Base interface for a TLS cipher suite.
 */
public interface TlsCipher
{
    /**
     * Return the maximum size for the plaintext given ciphertextlimit bytes of ciphertext.
     * @param ciphertextLimit the maximum number of bytes of ciphertext.
     * @return the maximum size of the plaintext for ciphertextlimit bytes of input.
     */
    int getPlaintextLimit(int ciphertextLimit);

    /**
     * Encrypt and MAC the passed in plain text using the current cipher suite.
     *
     * @param seqNo sequence number of the message represented by plaintext.
     * @param type content type of the message represented by plaintext.
     * @param plaintext array holding input plain text to the cipher.
     * @param offset offset into input array the plain text starts at.
     * @param len length of the plaintext in the array.
     * @return the resulting cipher text.
     * @throws IOException
     */
    byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
        throws IOException;

    /**
     * Validate and decrypt the passed in cipher text using the current cipher suite.
     *
     * @param seqNo sequence number of the message represented by ciphertext.
     * @param type content type of the message represented by ciphertext.
     * @param ciphertext  array holding input cipher text to the cipher.
     * @param offset offset into input array the cipher text starts at.
     * @param len length of the cipher text in the array.
     * @return the resulting plaintext.
     * @throws IOException
     */
    byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
        throws IOException;
}
