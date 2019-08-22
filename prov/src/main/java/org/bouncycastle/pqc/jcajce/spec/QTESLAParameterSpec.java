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
    public static final String PROVABLY_SECURE_I = QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_I);
    public static final String PROVABLY_SECURE_III = QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_III);

    private String securityCategory;

    /**
     * Base constructor.
     *
     * @param securityCategory the security category we want this parameterSpec to match.
     */
    public QTESLAParameterSpec(String securityCategory)
    {
        this.securityCategory = securityCategory;
    }

    /**
     * Return the security category.
     *
     * @return the security category.
     */
    public String getSecurityCategory()
    {
        return securityCategory;
    }
}
