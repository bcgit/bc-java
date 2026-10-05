package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

/**
 * Record number encryption mask generator for DTLS 1.3 (RFC 9147 4.2.3).
 * <p>
 * The mask is derived from the first 16 bytes of the protected record using the block function underlying the
 * negotiated AEAD (AES-ECB for AES-based AEADs, the ChaCha20 block function for ChaCha20-Poly1305), and is XORed
 * with the sequence number bytes of the unified header.
 * </p>
 */
public interface TlsRecordNumberMask
{
    /**
     * Set the sequence number key ("sn" traffic key) for this direction.
     */
    void setKey(byte[] key, int keyOff, int keyLen) throws IOException;

    /**
     * Generate the 16-byte mask for a record whose ciphertext starts at 'ciphertextOff'. At least 16 bytes of
     * ciphertext must be available. The mask is written to mask[maskOff..maskOff + 16).
     */
    void generateMask(byte[] ciphertext, int ciphertextOff, byte[] mask, int maskOff) throws IOException;
}
