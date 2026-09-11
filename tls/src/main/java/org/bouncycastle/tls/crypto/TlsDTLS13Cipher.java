package org.bouncycastle.tls.crypto;

import java.io.IOException;

/**
 * The optional DTLS 1.3 (RFC 9147) record protection extension to {@link TlsCipher}, implemented by ciphers
 * that can protect DTLS 1.3 records.
 */
public interface TlsDTLS13Cipher
{
    /**
     * Encode the passed in plaintext as a DTLS 1.3 protected record (RFC 9147 4). The supplied unified header is
     * the AEAD additional data; when its L bit is set the (zeroed) length field is filled in by this method. The
     * returned record holds the header, with record number encryption (RFC 9147 4.2.3) applied to its sequence
     * number bytes, followed by the encrypted record.
     *
     * @param seqNo the 64-bit record sequence number (the epoch is not included, unlike DTLS 1.2).
     * @param contentType the true content type, written into the DTLSInnerPlaintext.
     * @param header array holding the unified header with the sequence number in the clear.
     * @param headerOff offset of the header in the array.
     * @param headerLen length of the header.
     * @param plaintext array holding input plaintext to the cipher.
     * @param offset offset into input array the plaintext starts at.
     * @param len length of the plaintext in the array.
     * @return A {@link TlsEncodeResult} whose buffer holds the complete record (header followed by ciphertext),
     *         with 'recordType' set to the first byte of the unified header.
     * @throws IOException
     */
    TlsEncodeResult encodeDTLS13Plaintext(long seqNo, short contentType, byte[] header, int headerOff, int headerLen,
        byte[] plaintext, int offset, int len) throws IOException;

    /**
     * Decrypt (in place) the record number of a received DTLS 1.3 protected record (RFC 9147 4.2.3). The record
     * starts with its unified header; at least 16 bytes of ciphertext must follow the header.
     *
     * @param record array holding the received record.
     * @param recordOff offset of the record (its unified header) in the array.
     * @param recordLen length of the record.
     * @throws IOException
     */
    void decryptDTLS13RecordNumber(byte[] record, int recordOff, int recordLen) throws IOException;

    /**
     * Decode a received DTLS 1.3 protected record. The unified header (with the sequence number already decrypted)
     * at 'recordOff' is the AEAD additional data, and the ciphertext immediately follows it.
     *
     * @param seqNo the 64-bit record sequence number reconstructed by the caller (the epoch is not included).
     * @param record array holding the received record.
     * @param recordOff offset of the record (its unified header) in the array.
     * @param headerLen length of the unified header.
     * @param ciphertextLen length of the ciphertext following the header.
     * @return A {@link TlsDecodeResult} containing the result of decoding.
     * @throws IOException
     */
    TlsDecodeResult decodeDTLS13Ciphertext(long seqNo, byte[] record, int recordOff, int headerLen, int ciphertextLen)
        throws IOException;
}
