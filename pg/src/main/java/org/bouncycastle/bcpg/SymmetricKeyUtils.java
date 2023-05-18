package org.bouncycastle.bcpg;

public class SymmetricKeyUtils
    implements SymmetricKeyAlgorithmTags
{
    public static int getKeyLengthInBits(int algorithm)
    {
        switch (algorithm)
        {
        case NULL:
            throw new IllegalArgumentException("NULL is no encryption algorithm.");
        case DES:
            return 64;
        case IDEA:
        case CAST5:
        case BLOWFISH:
        case SAFER:
        case AES_128:
        case CAMELLIA_128:
            return 128;

        case TRIPLE_DES:
        case AES_192:
        case CAMELLIA_192:
            return 192;

        case AES_256:
        case TWOFISH:
        case CAMELLIA_256:
            return 256;
        default:
            throw new IllegalArgumentException("unknown symmetric algorithm: " + algorithm);
        }
    }

    public static int getKeyLengthInOctets(int algorithm)
    {
        return (getKeyLengthInBits(algorithm) + 7) / 8;
    }
}
