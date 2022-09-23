package org.bouncycastle.crypto;

public final class CryptoServicePurpose
{
    public static final CryptoServicePurpose AGREEMENT = new CryptoServicePurpose(0);
    public static final CryptoServicePurpose ENCRYPTION = new CryptoServicePurpose(1);
    public static final CryptoServicePurpose DECRYPTION = new CryptoServicePurpose(2);
    public static final CryptoServicePurpose KEYGEN = new CryptoServicePurpose(3);
    public static final CryptoServicePurpose SIGNING = new CryptoServicePurpose(4);
    public static final CryptoServicePurpose VERIFYING = new CryptoServicePurpose(5);
    public static final CryptoServicePurpose AUTHENTICATION = new CryptoServicePurpose(6);
    public static final CryptoServicePurpose VERIFICATION = new CryptoServicePurpose(7);
    public static final CryptoServicePurpose PRF = new CryptoServicePurpose(8);
    public static final CryptoServicePurpose ANY = new CryptoServicePurpose(9);

    private final int ord;

    private CryptoServicePurpose(int ord)
    {
        this.ord = ord;
    }

    public int ordinal()
    {
        return ord;
    }

    private static final CryptoServicePurpose[] vs = new CryptoServicePurpose[] { AGREEMENT, ENCRYPTION, DECRYPTION, KEYGEN, SIGNING, VERIFYING, AUTHENTICATION, VERIFICATION, PRF, ANY };

    public static CryptoServicePurpose[] values()
    {
	return vs;
    }
}
