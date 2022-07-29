package org.bouncycastle.crypto.signers;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.math.ec.ECCurve;

class Utils
{
    static CryptoServiceProperties getDefaultProperties(String algorithm, BigInteger p, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, bitsOfSecurity(p), forSigning);
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, ECCurve curve, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, bitsOfSecurity(curve), forSigning);
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, int bitsOfSecurity, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, bitsOfSecurity, forSigning);
    }

    static int bitsOfSecurity(BigInteger p)
    {
        int pBits = p.bitLength();

        if (pBits >= 2048)
        {
            return (pBits >= 3072) ?
                        ((pBits >= 7680) ?
                            ((pBits >= 15360) ? 256
                            : 192)
                        : 128)
                   : 112;
        }

        return (pBits >= 1024) ? 80 : 20;      // TODO: possibly a bit harsh...
    }

    static int bitsOfSecurity(ECCurve curve)
    {
        int pBits = curve.getFieldSize();

        return (pBits + 1) / 2;  // TODO: not quite right!
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

    private static class ECServiceProperties
        implements CryptoServiceProperties
    {
        private boolean forSigning;
        private final String algorithm;
        private int pBits;

        ECServiceProperties(String algorithm, BigInteger p, boolean forSigning)
        {
            this.algorithm = algorithm;
            this.pBits = p.bitLength();
            this.forSigning = forSigning;
        }

        public int bitsOfSecurity()
        {
            if (pBits >= 2048)
            {
                return (pBits >= 3072) ?
                            ((pBits >= 7680) ?
                                ((pBits >= 15360) ? 256
                                : 192)
                            : 128)
                       : 112;
            }

            return (pBits >= 1024) ? 80 : 20;      // TODO: possibly a bit harsh...
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
