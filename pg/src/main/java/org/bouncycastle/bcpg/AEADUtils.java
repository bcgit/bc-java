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
    static int getAuthTagLength(int aeadAlgorithmTag)
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
}
