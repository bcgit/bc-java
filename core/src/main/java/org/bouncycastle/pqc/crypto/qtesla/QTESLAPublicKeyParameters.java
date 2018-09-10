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

    public String getAlgorithm()
    {

        if (this.securityCategory == QTESLASigner.HEURISTIC_I)
        {

            return "heuristic_qTESLA_security_category_I";

        }

        if (this.securityCategory == QTESLASigner.HEURISTIC_III_SIZE)
        {

            return "heuristic_qTESLA_security_category_III_option_for_size";

        }

        if (this.securityCategory == QTESLASigner.HEURISTIC_III_SPEED)
        {

            return "heuristic_qTESLA_security_category_III_option_for_speed";

        }

        if (this.securityCategory == QTESLASigner.PROVABLY_SECURE_I)
        {

            return "provably_secure_qTESLA_security_category_I";

        }

        if (this.securityCategory == QTESLASigner.PROVABLY_SECURE_III)
        {

            return "provably_secure_qTESLA_security_category_III";

        }

        return null;

    }

    public byte[] getPublicData()
    {
        return Arrays.clone(publicKey);
    }
}
