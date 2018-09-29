package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;

public class QTESLAParameterSpec
    implements AlgorithmParameterSpec
{
    public static final int HEURISTIC_I = QTESLASecurityCategory.HEURISTIC_I;
    public static final int HEURISTIC_III_SIZE = QTESLASecurityCategory.HEURISTIC_III_SIZE;
    public static final int HEURISTIC_III_SPEED = QTESLASecurityCategory.HEURISTIC_III_SPEED;
    public static final int PROVABLY_SECURE_I = QTESLASecurityCategory.PROVABLY_SECURE_I;
    public static final int PROVABLY_SECURE_III = QTESLASecurityCategory.PROVABLY_SECURE_III;

    private int securityCategory;

    public QTESLAParameterSpec(int securityCategory)
    {
        this.securityCategory = securityCategory;
    }

    public int getSecurityCategory()
    {
        return securityCategory;
    }
}
