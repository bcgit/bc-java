package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.math.ec.ECCurve;

class Utils
{
    static CryptoServiceProperties getDefaultProperties(String algorithm, BigInteger p)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(p));
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, ECCurve curve)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(curve));
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, int bitsOfSecurity)
    {
        return new DefaultServiceProperties(algorithm, bitsOfSecurity);
    }

    // Service Definitions
    private static class DefaultServiceProperties
        implements CryptoServiceProperties
    {
        private final String algorithm;
        private final int bitsOfSecurity;

        DefaultServiceProperties(String algorithm, int bitsOfSecurity)
        {
            this.algorithm = algorithm;
            this.bitsOfSecurity = bitsOfSecurity;
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
            return CryptoServicePurpose.ENCRYPTION;
        }
    }
}
