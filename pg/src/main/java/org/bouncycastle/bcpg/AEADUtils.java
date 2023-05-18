package org.bouncycastle.bcpg;

public class AEADUtils
    implements AEADAlgorithmTags
{
    private AEADUtils()
    {
    }

    /**
     * Return the length of the IV used by the given AEAD algorithm in octets.
     *
     * @param aeadAlgorithmTag AEAD algorithm identifier
     * @return length of the IV
     */
    public static int getIVLength(int aeadAlgorithmTag)
    {
        switch (aeadAlgorithmTag)
        {
        case EAX:
            return 16;
        case OCB:
            return 15;
        case GCM:
            return 12;
        default:
            throw new IllegalArgumentException("Invalid AEAD algorithm tag: " + aeadAlgorithmTag);
        }
    }

    /**
     * Return the length of the authentication tag used by the given AEAD algorithm in octets.
     *
     * @param aeadAlgorithmTag AEAD algorithm identifier
     * @return length of the auth tag
     */
    public static int getAuthTagLength(int aeadAlgorithmTag)
    {
        switch (aeadAlgorithmTag)
        {
        case EAX:
        case OCB:
        case GCM:
            return 16;
        default:
            throw new IllegalArgumentException("Invalid AEAD algorithm tag: " + aeadAlgorithmTag);
        }
    }

    /**
     * Split a given byte array containing <pre>m</pre> bytes of key and <pre>n-8</pre> bytes of IV into
     * two separate byte arrays.
     * <pre>m</pre> is the key length of the cipher algorithm, while <pre>n</pre> is the IV length of the AEAD algorithm.
     * Note, that the IV is filled with <pre>n-8</pre> bytes only, the remainder is left as 0s.
     * Return an array of both arrays with the key and index 0 and the IV at index 1.
     *
     * @param messageKeyAndIv <pre>m+n-8</pre> bytes of concatenated message key and IV
     * @param cipherAlgo      symmetric cipher algorithm
     * @param aeadAlgo        AEAD algorithm
     * @return array of arrays containing message key and IV
     */
    public static byte[][] splitMessageKeyAndIv(byte[] messageKeyAndIv, int cipherAlgo, int aeadAlgo)
    {
        int keyLen = SymmetricKeyUtils.getKeyLengthInOctets(cipherAlgo);
        int ivLen = AEADUtils.getIVLength(aeadAlgo);
        byte[] messageKey = new byte[keyLen];
        byte[] iv = new byte[ivLen];
        System.arraycopy(messageKeyAndIv, 0, messageKey, 0, messageKey.length);
        System.arraycopy(messageKeyAndIv, messageKey.length, iv, 0, ivLen - 8);

        return new byte[][]{messageKey, iv};
    }
}
