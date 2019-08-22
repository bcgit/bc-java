package org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Key-pair generator for qTESLA keys.
 */
public final class QTESLAKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    /**
     * qTESLA Security Category
     */
    private int securityCategory;
    private SecureRandom secureRandom;

    /**
     * Initialize the generator with a security category and a source of randomness.
     *
     * @param param a {@link QTESLAKeyGenerationParameters} object.
     */
    public void init(
        KeyGenerationParameters param)
    {
        QTESLAKeyGenerationParameters parameters = (QTESLAKeyGenerationParameters)param;

        this.secureRandom = parameters.getRandom();
        this.securityCategory = parameters.getSecurityCategory();
    }

    /**
     * Generate a key-pair.
     *
     * @return a matching key-pair consisting of (QTESLAPublicKeyParameters, QTESLAPrivateKeyParameters).
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] privateKey = allocatePrivate(securityCategory);
        byte[] publicKey = allocatePublic(securityCategory);

        switch (securityCategory)
        {
        case QTESLASecurityCategory.PROVABLY_SECURE_I:
            QTesla1p.generateKeyPair(publicKey, privateKey, secureRandom);
            break;

        case QTESLASecurityCategory.PROVABLY_SECURE_III:
            QTesla3p.generateKeyPair(publicKey, privateKey, secureRandom);
            break;

        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }

        return new AsymmetricCipherKeyPair(new QTESLAPublicKeyParameters(securityCategory, publicKey), new QTESLAPrivateKeyParameters(securityCategory, privateKey));
    }

    private byte[] allocatePrivate(int securityCategory)
    {
        return new byte[QTESLASecurityCategory.getPrivateSize(securityCategory)];
    }

    private byte[] allocatePublic(int securityCategory)
    {
        return new byte[QTESLASecurityCategory.getPublicSize(securityCategory)];
    }
}
