package org.bouncycastle.pqc.crypto.qtesla;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

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

    public int getSecurityCategory()
    {
        return this.securityCategory;
    }

    public byte[] getSecret()
    {
        return Arrays.clone(privateKey);
    }
}
