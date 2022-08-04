package org.bouncycastle.crypto.signers;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.math.ec.ECCurve;

class Utils
{
    static CryptoServiceProperties getDefaultProperties(String algorithm, BigInteger p, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(p), forSigning);
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, ECCurve curve, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(curve), forSigning);
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, int bitsOfSecurity, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, bitsOfSecurity, forSigning);
    }

    // Service Definitions
    private static class DefaultServiceProperties
        implements CryptoServiceProperties
    {
        private boolean forSigning;
        private final String algorithm;
        private final int bitsOfSecurity;

        DefaultServiceProperties(String algorithm, int bitsOfSecurity, boolean forSigning)
        {
            this.algorithm = algorithm;
            this.bitsOfSecurity = bitsOfSecurity;
            this.forSigning = forSigning;
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
            return forSigning ? CryptoServicePurpose.SIGNING : CryptoServicePurpose.VERIFYING;
        }
    }
}
