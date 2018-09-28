package org.bouncycastle.pqc.crypto.qtesla;

public class QTESLASecurityCategory
{
    public static final int HEURISTIC_I = 0;
    public static final int HEURISTIC_III_SIZE = 1;
    public static final int HEURISTIC_III_SPEED = 2;
    public static final int PROVABLY_SECURE_I = 3;
    public static final int PROVABLY_SECURE_III = 4;

    private QTESLASecurityCategory()
    {

    }

    static void validate(int securityCategory)
    {
        switch (securityCategory)
        {
        case HEURISTIC_I:
        case HEURISTIC_III_SIZE:
        case HEURISTIC_III_SPEED:
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
        case HEURISTIC_I:
            return Polynomial.PRIVATE_KEY_I;
        case HEURISTIC_III_SIZE:
            return Polynomial.PRIVATE_KEY_III_SIZE;
        case HEURISTIC_III_SPEED:
            return Polynomial.PRIVATE_KEY_III_SPEED;
        case PROVABLY_SECURE_I:
            return Polynomial.PRIVATE_KEY_I_P;
        case PROVABLY_SECURE_III:
            return Polynomial.PRIVATE_KEY_III_P;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getPublicSize(int securityCategory)
    {
        switch (securityCategory)
        {
        case HEURISTIC_I:
            return Polynomial.PUBLIC_KEY_I;
        case HEURISTIC_III_SIZE:
            return Polynomial.PUBLIC_KEY_III_SIZE;
        case HEURISTIC_III_SPEED:
            return Polynomial.PUBLIC_KEY_III_SPEED;
        case PROVABLY_SECURE_I:
            return Polynomial.PUBLIC_KEY_I_P;
        case PROVABLY_SECURE_III:
            return Polynomial.PUBLIC_KEY_III_P;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getSignatureSize(int securityCategory)
    {
        switch (securityCategory)
        {
        case HEURISTIC_I:
            return Polynomial.SIGNATURE_I;
        case HEURISTIC_III_SIZE:
            return Polynomial.SIGNATURE_III_SIZE;
        case HEURISTIC_III_SPEED:
            return Polynomial.SIGNATURE_III_SPEED;
        case PROVABLY_SECURE_I:
            return Polynomial.SIGNATURE_I_P;
        case PROVABLY_SECURE_III:
            return Polynomial.SIGNATURE_III_P;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static String getName(int securityCategory)
    {
        switch (securityCategory)
        {
        case HEURISTIC_I:
            return "heuristic_qTESLA_security_category_I";
        case HEURISTIC_III_SIZE:
            return "heuristic_qTESLA_security_category_III_option_for_size";
        case HEURISTIC_III_SPEED:
            return "heuristic_qTESLA_security_category_III_option_for_speed";
        case PROVABLY_SECURE_I:
            return "provably_secure_qTESLA_security_category_I";
        case PROVABLY_SECURE_III:
            return "provably_secure_qTESLA_security_category_III";
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }
}
