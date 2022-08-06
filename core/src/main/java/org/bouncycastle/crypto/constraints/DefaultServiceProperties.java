package org.bouncycastle.crypto.constraints;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;

public class DefaultServiceProperties
    implements CryptoServiceProperties
{
    private final String algorithm;
    private final int bitsOfSecurity;
    private final CipherParameters params;
    private final CryptoServicePurpose purpose;

    public DefaultServiceProperties(String algorithm, int bitsOfSecurity)
    {
        this(algorithm, bitsOfSecurity, null, CryptoServicePurpose.ANY);
    }

    public DefaultServiceProperties(String algorithm, int bitsOfSecurity, CipherParameters params)
    {
        this(algorithm, bitsOfSecurity, params, CryptoServicePurpose.ANY);
    }

    public DefaultServiceProperties(String algorithm, int bitsOfSecurity, CipherParameters params, CryptoServicePurpose purpose)
    {
        this.algorithm = algorithm;
        this.bitsOfSecurity = bitsOfSecurity;
        this.params = params;
        this.purpose = purpose;
    }

    public int bitsOfSecurity()
    {
        return bitsOfSecurity;
    }

    public String getServiceName()
    {
        return algorithm;
    }

    public CryptoServicePurpose getPurpose()
    {
        return purpose;
    }

    public CipherParameters getParams()
    {
        return params;
    }
}
