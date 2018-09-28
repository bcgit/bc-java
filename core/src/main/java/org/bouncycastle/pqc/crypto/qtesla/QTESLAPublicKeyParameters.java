package org.bouncycastle.pqc.crypto.qtesla;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * qTESLA public key
 */
public final class QTESLAPublicKeyParameters
    extends AsymmetricKeyParameter
{
    /**
     * qTESLA Security Category
     */
    private int securityCategory;

    /**
     * Text of the qTESLA Public Key
     */
    private byte[] publicKey;

    /**
     * Base constructor.
     *
     * @param securityCategory the security category for the passed in public key data.
     * @param publicKey the public key data.
     */
    public QTESLAPublicKeyParameters(int securityCategory, byte[] publicKey)
    {
        super(false);

        if (publicKey.length != QTESLASecurityCategory.getPublicSize(securityCategory))
        {
            throw new IllegalArgumentException("invalid key size for security category");
        }

        this.securityCategory = securityCategory;
        this.publicKey = Arrays.clone(publicKey);

    }

    /**
     * Return the security category for this key.
     *
     * @return the key's security category.
     */
    public int getSecurityCategory()
    {
        return this.securityCategory;
    }

    /**
     * Return the key's public value.
     *
     * @return key public data.
     */
    public byte[] getPublicData()
    {
        return Arrays.clone(publicKey);
    }
}
