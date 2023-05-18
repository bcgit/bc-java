package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.AEADUtils;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.util.Arrays;

public class AEADUtil {

    /**
     * Generate a nonce by xor-ing the given iv with the chunk index.
     *
     * @param iv initialization vector
     * @param chunkIndex chunk index
     * @return nonce
     */
    protected static byte[] getNonce(byte[] iv, long chunkIndex)
    {
        byte[] nonce = Arrays.clone(iv);

        xorChunkId(nonce, chunkIndex);

        return nonce;
    }

    /**
     * XOR the byte array with the chunk index in-place.
     *
     * @param nonce byte array
     * @param chunkIndex chunk index
     */
    protected static void xorChunkId(byte[] nonce, long chunkIndex)
    {
        int index = nonce.length - 8;

        nonce[index++] ^= (byte)(chunkIndex >> 56);
        nonce[index++] ^= (byte)(chunkIndex >> 48);
        nonce[index++] ^= (byte)(chunkIndex >> 40);
        nonce[index++] ^= (byte)(chunkIndex >> 32);
        nonce[index++] ^= (byte)(chunkIndex >> 24);
        nonce[index++] ^= (byte)(chunkIndex >> 16);
        nonce[index++] ^= (byte)(chunkIndex >> 8);
        nonce[index] ^= (byte)(chunkIndex);
    }

    /**
     * Calculate an actual chunk length from the encoded chunk size.
     *
     * @param chunkSize encoded chunk size
     * @return decoded length
     */
    protected static long getChunkLength(int chunkSize)
    {
        return 1L << (chunkSize + 6);
    }

    /**
     * Derived a message key and IV from the given session key.
     *
     * @param aeadAlgo AEAD algorithm
     * @param cipherAlgo symmetric cipher algorithm
     * @param sessionKey session key
     * @param salt salt
     * @param hkdfInfo HKDF info
     * @return an array of byte arrays, the message key is at index 0, the IV at index 1.
     * @throws PGPException
     */
    public static byte[][] deriveAndSplitMessageKeyAndIv(int aeadAlgo,
                                                         int cipherAlgo,
                                                         byte[] sessionKey,
                                                         byte[] salt,
                                                         byte[] hkdfInfo)
            throws PGPException
    {
        byte[] messageKeyAndIv = deriveMessageKeyAndIv(aeadAlgo, cipherAlgo, sessionKey, salt, hkdfInfo);
        return splitMessageKeyAndIv(messageKeyAndIv, cipherAlgo, aeadAlgo);
    }

    /**
     * Derive a message key and IV from the given session key.
     * The result is a byte array containing the key bytes followed by the IV.
     * To split them, use {@link #splitMessageKeyAndIv(byte[], int, int)}.
     *
     * @param aeadAlgo AEAD algorithm
     * @param cipherAlgo symmetric cipher algorithm
     * @param sessionKey session key
     * @param salt salt
     * @param hkdfInfo HKDF info
     * @return message key and appended IV
     * @throws PGPException
     */
    public static byte[] deriveMessageKeyAndIv(int aeadAlgo, int cipherAlgo, byte[] sessionKey, byte[] salt, byte[] hkdfInfo)
            throws PGPException
    {
        // Is it okay to have this common logic be implemented using BCs lightweight API?
        // Should we move it to BcAEADUtil instead and also provide a JCE implementation?
        HKDFParameters hkdfParameters = new HKDFParameters(sessionKey, salt, hkdfInfo);
        HKDFBytesGenerator hkdfGen = new HKDFBytesGenerator(new SHA256Digest());

        hkdfGen.init(hkdfParameters);
        int keyLen = SymmetricKeyUtils.getKeyLengthInOctets(cipherAlgo);
        int ivLen = AEADUtils.getIVLength(aeadAlgo);
        byte[] messageKeyAndIv = new byte[keyLen + ivLen - 8];
        hkdfGen.generateBytes(messageKeyAndIv, 0, messageKeyAndIv.length);
        return messageKeyAndIv;
    }

    /**
     * Split a given byte array containing <pre>m</pre> bytes of key and <pre>n-8</pre> bytes of IV into
     * two separate byte arrays.
     * <pre>m</pre> is the key length of the cipher algorithm, while <pre>n</pre> is the IV length of the AEAD algorithm.
     * Note, that the IV is filled with <pre>n-8</pre> bytes only, the remainder is left as 0s.
     * Return an array of both arrays with the key and index 0 and the IV at index 1.
     *
     * @param messageKeyAndIv <pre>m+n-8</pre> bytes of concatenated message key and IV
     * @param cipherAlgo symmetric cipher algorithm
     * @param aeadAlgo AEAD algorithm
     * @return array of arrays containing message key and IV
     * @throws PGPException
     */
    public static byte[][] splitMessageKeyAndIv(byte[] messageKeyAndIv, int cipherAlgo, int aeadAlgo)
            throws PGPException
    {
        int keyLen = SymmetricKeyUtils.getKeyLengthInOctets(cipherAlgo);
        int ivLen = AEADUtils.getIVLength(aeadAlgo);
        byte[] messageKey = new byte[keyLen];
        byte[] iv = new byte[ivLen];
        System.arraycopy(messageKeyAndIv, 0, messageKey, 0, messageKey.length);
        System.arraycopy(messageKeyAndIv, messageKey.length, iv, 0, ivLen - 8);

        return new byte[][] {messageKey, iv};
    }

}
