package org.bouncycastle.kmip.wire.enumeration;


// Enum representing cryptographic usage mask
public enum KMIPCryptographicUsageMask
    implements KMIPEnumeration
{
    Sign(0x00000001),
    Verify(0x00000002),
    Encrypt(0x00000004),
    Decrypt(0x00000008),
    WrapKey(0x00000010),
    UnwrapKey(0x00000020),
    MacGenerate(0x00000080),
    MacVerify(0x00000100),
    DeriveKey(0x00000200),
    KeyAgreement(0x00000800),
    CertificateSign(0x00001000),
    CrlSign(0x00002000),
    Authenticate(0x00100000),
    Unrestricted(0x00200000),
    FpeEncrypt(0x00400000),
    FpeDecrypt(0x00800000);

    private final int value;

    KMIPCryptographicUsageMask(int value)
    {
        this.value = value;
    }

    public int getValue()
    {
        return value;
    }

    public static KMIPCryptographicUsageMask fromValue(int value)
    {
        for (KMIPCryptographicUsageMask algorithm : KMIPCryptographicUsageMask.values())
        {
            if (algorithm.value == value)
            {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unknown cryptographic algorithm value: " + value);
    }
}

