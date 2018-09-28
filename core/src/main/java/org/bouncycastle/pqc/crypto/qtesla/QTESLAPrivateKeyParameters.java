package org.bouncycastle.pqc.crypto.qtesla;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * qTESLA private key
 */
public final class QTESLAPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    /**
     * qTESLA Security Category (From 4 To 8)
     */
    private int securityCategory;

    /**
     * Text of the qTESLA Private Key
     */
    private byte[] privateKey;

    /**
     * Base constructor.
     *
     * @param securityCategory the security category for the passed in public key data.
     * @param privateKey the private key data.
     */
    public QTESLAPrivateKeyParameters(int securityCategory, byte[] privateKey)
    {
        super(true);

        if (privateKey.length != QTESLASecurityCategory.getPrivateSize(securityCategory))
        {
            throw new IllegalArgumentException("invalid key size for security category");
        }

        this.securityCategory = securityCategory;
        this.privateKey = Arrays.clone(privateKey);
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
     * Return the key's secret value.
     *
     * @return key private data.
     */
    public byte[] getSecret()
    {
        return Arrays.clone(privateKey);
    }
}
