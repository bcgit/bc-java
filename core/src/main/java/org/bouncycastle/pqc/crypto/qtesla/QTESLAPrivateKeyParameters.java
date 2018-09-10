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

    public byte[] getSecret()
    {
        return Arrays.clone(privateKey);
    }
}
