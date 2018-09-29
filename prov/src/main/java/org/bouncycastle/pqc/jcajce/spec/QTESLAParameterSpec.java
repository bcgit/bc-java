package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;

/**
 * qTESLA parameter details. These are divided up on the basis of the security categories for each
 * individual parameter set.
 */
public class QTESLAParameterSpec
    implements AlgorithmParameterSpec
{
    /**
     * Available security categories.
     */
    public static final int HEURISTIC_I = QTESLASecurityCategory.HEURISTIC_I;
    public static final int HEURISTIC_III_SIZE = QTESLASecurityCategory.HEURISTIC_III_SIZE;
    public static final int HEURISTIC_III_SPEED = QTESLASecurityCategory.HEURISTIC_III_SPEED;
    public static final int PROVABLY_SECURE_I = QTESLASecurityCategory.PROVABLY_SECURE_I;
    public static final int PROVABLY_SECURE_III = QTESLASecurityCategory.PROVABLY_SECURE_III;

    private int securityCategory;

    /**
     * Base constructor.
     *
     * @param securityCategory the security category we want this parameterSpec to match.
     */
    public QTESLAParameterSpec(int securityCategory)
    {
        this.securityCategory = securityCategory;
    }

    /**
     * Return the security category.
     *
     * @return the security category.
     */
    public int getSecurityCategory()
    {
        return securityCategory;
    }
}
