package org.bouncycastle.pqc.crypto.qtesla;

/**
 * The qTESLA security categories.
 */
public class QTESLASecurityCategory
{
    public static final int HEURISTIC_I = 0;
    public static final int HEURISTIC_II = 1;
    public static final int HEURISTIC_III = 2;
    public static final int HEURISTIC_V = 3;
    public static final int HEURISTIC_V_SIZE = 4;
    public static final int HEURISTIC_P_I = 5;
    public static final int HEURISTIC_P_III = 6;


    private QTESLASecurityCategory()
    {
    }

    static void validate(int securityCategory)
    {
        switch (securityCategory)
        {
        case HEURISTIC_I:
        case HEURISTIC_II:
        case HEURISTIC_III:
        case HEURISTIC_V:
        case HEURISTIC_V_SIZE:
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
        case HEURISTIC_I:
            return QTesla1.CRYPTO_SECRETKEYBYTES;
        case HEURISTIC_II:
            return QTesla2.CRYPTO_SECRETKEYBYTES;
        case HEURISTIC_III:
            return QTesla3.CRYPTO_SECRETKEYBYTES;
        case HEURISTIC_V:
            return QTesla5.CRYPTO_SECRETKEYBYTES;
        case HEURISTIC_V_SIZE:
            return QTesla5Size.CRYPTO_SECRETKEYBYTES;
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
        case HEURISTIC_I:
            return QTesla1.CRYPTO_PUBLICKEYBYTES;
        case HEURISTIC_II:
            return QTesla2.CRYPTO_PUBLICKEYBYTES;
        case HEURISTIC_III:
            return QTesla3.CRYPTO_PUBLICKEYBYTES;
        case HEURISTIC_V:
            return QTesla5.CRYPTO_PUBLICKEYBYTES;
        case HEURISTIC_V_SIZE:
            return QTesla5Size.CRYPTO_PUBLICKEYBYTES;
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
        case HEURISTIC_I:
            return QTesla1.SIGNATURE_SIZE;

        case HEURISTIC_II:
            return QTesla2.CRYPTO_BYTES;
        case HEURISTIC_III:
            return QTesla3.CRYPTO_BYTES;
        case HEURISTIC_V:
            return QTesla5.CRYPTO_BYTES;
        case HEURISTIC_V_SIZE:
            return QTesla5Size.CRYPTO_BYTES;
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
        case HEURISTIC_I:
            return "qTESLA-I";
        case HEURISTIC_II:
            return "qTESLA-II";
        case HEURISTIC_III:
            return "qTESLA-III";
        case HEURISTIC_V:
            return "qTESLA-V";
        case HEURISTIC_V_SIZE:
            return "qTESLA-V-SIZE";
        case HEURISTIC_P_I:
            return "qTESLA-p-I";
        case HEURISTIC_P_III:
            return "qTESLA-p-III";
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }
}
