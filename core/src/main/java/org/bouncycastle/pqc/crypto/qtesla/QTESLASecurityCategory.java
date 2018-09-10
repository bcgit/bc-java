package org.bouncycastle.pqc.crypto.qtesla;

public class QTESLASecurityCategory
{
    public static final int HEURISTIC_I = QTESLASigner.HEURISTIC_I;
    public static final int HEURISTIC_III_SIZE = QTESLASigner.HEURISTIC_III_SIZE;
    public static final int HEURISTIC_III_SPEED = QTESLASigner.HEURISTIC_III_SPEED;
    public static final int PROVABLY_SECURE_I = QTESLASigner.PROVABLY_SECURE_I;
    public static final int PROVABLY_SECURE_III = QTESLASigner.PROVABLY_SECURE_III;

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
}
