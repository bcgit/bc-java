package org.bouncycastle.pqc.crypto.qtesla;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public final class QTESLAPublicKeyParameters
    extends AsymmetricKeyParameter
{
    /**
     * qTESLA Security Category (From 4 To 8)
     */
    private int securityCategory;

    /**
     * Text of the qTESLA Public Key
     */
    private byte[] publicKey;

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

    public int getSecurityCategory()
    {

        return this.securityCategory;

    }

    public byte[] getPublicData()
    {
        return Arrays.clone(publicKey);
    }
}
