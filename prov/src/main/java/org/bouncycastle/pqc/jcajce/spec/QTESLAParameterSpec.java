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
    public static final String HEURISTIC_I = QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_I);
    public static final String HEURISTIC_II = QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_II);
    public static final String HEURISTIC_III = QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III);
    public static final String HEURISTIC_V = QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_V);
    public static final String HEURISTIC_V_SIZE = QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_V_SIZE);
    public static final String HEURISTIC_P_I = QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_P_I);
    public static final String HEURISTIC_P_III = QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_P_III);

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
