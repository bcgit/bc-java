package org.bouncycastle.crypto;

public enum CryptoServicePurpose
{
    AGREEMENT(0),
    ENCRYPTION(1),
    DECRYPTION(2),
    KEYGEN(3),
    SIGNING(4),         // for signatures (and digests)
    VERIFYING(5),
    AUTHENTICATION(6),  // for MACs (and digests)
    VERIFICATION(7),
    PRF(8),
    ANY(9);

    private final int code;

    CryptoServicePurpose(int code)
    {
        this.code = code;
    }

    /**
     * The stable numeric code for this purpose. It is written as the trailing byte of a digest's
     * encoded state, so - unlike {@link #ordinal()} - it must not shift if the constants are ever
     * reordered; each constant carries its own code for that reason.
     */
    public int getCode()
    {
        return code;
    }

    /**
     * Return the purpose with the given {@link #getCode() code}.
     *
     * @throws IllegalArgumentException if no purpose has that code.
     */
    public static CryptoServicePurpose forCode(int code)
    {
        for (CryptoServicePurpose purpose : values())
        {
            if (purpose.code == code)
            {
                return purpose;
            }
        }

        throw new IllegalArgumentException("unknown CryptoServicePurpose code: " + code);
    }
}
