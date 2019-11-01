package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.ProtocolVersion;

/**
 * Base interface for a TLS cipher suite.
 */
public interface TlsCipher
{
    /**
     * Return the maximum input size for a ciphertext given a maximum output size for the plaintext
     * of plaintextLimit bytes.
     * 
     * @param plaintextLimit
     *            the maximum output size for the plaintext.
     * @return the maximum input size of the ciphertext for plaintextlimit bytes of output.
     */
    int getCiphertextDecodeLimit(int plaintextLimit);

    /**
     * Return the maximum output size for a ciphertext given an actual input plaintext size of
     * plaintextLength bytes and a maximum input plaintext size of plaintextLimit bytes.
     * 
     * @param plaintextLength
     *            the actual input size for the plaintext.
     * @param plaintextLimit
     *            the maximum input size for the plaintext.
     * @return the maximum output size of the ciphertext for plaintextlimit bytes of input.
     */
    int getCiphertextEncodeLimit(int plaintextLength, int plaintextLimit);

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
     * @param contentType content type of the message represented by plaintext.
     * @param recordVersion {@link ProtocolVersion} used for the record.
     * @param headerAllocation extra bytes to allocate at start of returned byte array.
     * @param plaintext array holding input plain text to the cipher.
     * @param offset offset into input array the plain text starts at.
     * @param len length of the plaintext in the array.
     * @return A {@link TlsEncodeResult} containing the result of encoding (after 'headerAllocation' unused bytes).
     * @throws IOException
     */
    TlsEncodeResult encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion, int headerAllocation,
        byte[] plaintext, int offset, int len) throws IOException;

    /**
     * Validate and decrypt the passed in cipher text using the current cipher suite.
     *
     * @param seqNo sequence number of the message represented by ciphertext.
     * @param recordType content type used in the record for this message.
     * @param recordVersion {@link ProtocolVersion} used for the record.
     * @param ciphertext  array holding input cipher text to the cipher.
     * @param offset offset into input array the cipher text starts at.
     * @param len length of the cipher text in the array.
     * @return A {@link TlsDecodeResult} containing the result of decoding.
     * @throws IOException
     */
    TlsDecodeResult decodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion, byte[] ciphertext,
        int offset, int len) throws IOException;

    void rekeyDecoder() throws IOException;

    void rekeyEncoder() throws IOException;

    boolean usesOpaqueRecordType();
}
