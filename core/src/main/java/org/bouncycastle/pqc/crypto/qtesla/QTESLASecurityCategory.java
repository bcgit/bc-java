package org.bouncycastle.pqc.crypto.qtesla;

/**
 * The qTESLA security categories.
 */
public class QTESLASecurityCategory
{

    public static final int HEURISTIC_P_I = 5;
    public static final int HEURISTIC_P_III = 6;


    private QTESLASecurityCategory()
    {
    }

    static void validate(int securityCategory)
    {
        switch (securityCategory)
        {
        case HEURISTIC_P_I:
        case HEURISTIC_P_III:
            break;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getPrivateSize(int securityCategory)
    {
        switch (securityCategory)
        {
        case HEURISTIC_P_I:
            return QTesla1p.CRYPTO_SECRETKEYBYTES;
        case HEURISTIC_P_III:
            return QTesla3p.CRYPTO_SECRETKEYBYTES;

        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getPublicSize(int securityCategory)
    {
        switch (securityCategory)
        {
        case HEURISTIC_P_I:
            return QTesla1p.CRYPTO_PUBLICKEYBYTES;
        case HEURISTIC_P_III:
            return QTesla3p.CRYPTO_PUBLICKEYBYTES;

        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getSignatureSize(int securityCategory)
    {
        switch (securityCategory)
        {

        case HEURISTIC_P_I:
            return QTesla1p.CRYPTO_BYTES;
        case HEURISTIC_P_III:
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
        case HEURISTIC_P_I:
            return "qTESLA-p-I";
        case HEURISTIC_P_III:
            return "qTESLA-p-III";
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }
}
