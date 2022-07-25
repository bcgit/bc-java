package org.bouncycastle.crypto;

public interface CryptoServiceProperties
{
    enum Purpose
    {
        ENCRYPTION,
        DECRYPTION,
        SIGNING,
        VERIFYING,
        BOTH
    }

    int bitsOfSecurity();

    String getServiceName();

    Purpose getPurpose();
}
