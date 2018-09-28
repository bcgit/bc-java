package org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * qTESLA key-pair generation parameters.
 */
public class QTESLAKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final int securityCategory;

    /**
     * Base constructor - provide the qTESLA security category and a source of randomness.
     *
     * @param securityCategory the security category to generate the parameters for.
     * @param random           the random byte source.
     */
    public QTESLAKeyGenerationParameters(int securityCategory, SecureRandom random)
    {
        super(random, -1);

        QTESLASecurityCategory.getPrivateSize(securityCategory);  // check the category is valid

        this.securityCategory = securityCategory;
    }

    /**
      * Return the security category for these parameters.
      *
      * @return the security category for keys generated using these parameters.
      */
    public int getSecurityCategory()
    {
        return securityCategory;
    }
}
