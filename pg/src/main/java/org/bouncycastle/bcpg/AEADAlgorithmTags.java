package org.bouncycastle.bcpg;

public interface AEADAlgorithmTags
{
    int EAX = 1;    // EAX (IV len: 16 octets, Tag len: 16 octets)
    int OCB = 2;    // OCB (IV len: 15 octets, Tag len: 16 octets)
    int GCM = 3;    // GCM (IV len: 12 octets, Tag len: 16 octets)

    /**
     * Return the length of the IV used by the given AEAD algorithm in octets.
     *
     * @param aeadAlgorithmTag AEAD algorithm identifier
     * @return length of the IV
     */
    static int getIvLength(int aeadAlgorithmTag)
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
