package org.bouncycastle.pqc.crypto.qtesla;

/**
 * The qTESLA security categories.
 */
public class QTESLASecurityCategory
{
    public static final int PROVABLY_SECURE_I = 5;
    public static final int PROVABLY_SECURE_III = 6;

    private QTESLASecurityCategory()
    {
    }

    static void validate(int securityCategory)
    {
        switch (securityCategory)
        {
        case PROVABLY_SECURE_I:
        case PROVABLY_SECURE_III:
            break;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getPrivateSize(int securityCategory)
    {
        switch (securityCategory)
        {
        case PROVABLY_SECURE_I:
            return QTesla1p.CRYPTO_SECRETKEYBYTES;
        case PROVABLY_SECURE_III:
            return QTesla3p.CRYPTO_SECRETKEYBYTES;

        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getPublicSize(int securityCategory)
    {
        switch (securityCategory)
        {
        case PROVABLY_SECURE_I:
            return QTesla1p.CRYPTO_PUBLICKEYBYTES;
        case PROVABLY_SECURE_III:
            return QTesla3p.CRYPTO_PUBLICKEYBYTES;

        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getSignatureSize(int securityCategory)
    {
        switch (securityCategory)
        {

        case PROVABLY_SECURE_I:
            return QTesla1p.CRYPTO_BYTES;
        case PROVABLY_SECURE_III:
            return QTesla3p.CRYPTO_BYTES;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    /**
     * Return a standard name for the security category.
     *
     * @param securityCategory the category of interest.
     * @return the name for the category.
     */
    public static String getName(int securityCategory)
    {
        switch (securityCategory)
        {
        case PROVABLY_SECURE_I:
            return "qTESLA-p-I";
        case PROVABLY_SECURE_III:
            return "qTESLA-p-III";
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }
}
