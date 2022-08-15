package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.Digest;

class Utils
{
    static CryptoServiceProperties getDefaultProperties(Digest digest, CryptoServicePurpose purpose)
    {
        return new DefaultProperties(digest.getDigestSize() * 4, digest.getAlgorithmName(), purpose);
    }

    static CryptoServiceProperties getDefaultProperties(Digest digest, int prfBitsOfSecurity, CryptoServicePurpose purpose)
    {
        return new DefaultPropertiesWithPRF(digest.getDigestSize() * 4, prfBitsOfSecurity, digest.getAlgorithmName(), purpose);
    }

    // Service Definitions
    private static class DefaultPropertiesWithPRF
        implements CryptoServiceProperties
    {
        private final int bitsOfSecurity;
        private final int prfBitsOfSecurity;
        private final String algorithmName;
        private final CryptoServicePurpose purpose;

        public DefaultPropertiesWithPRF(int bitsOfSecurity, int prfBitsOfSecurity, String algorithmName, CryptoServicePurpose purpose)
        {
            this.bitsOfSecurity = bitsOfSecurity;
            this.prfBitsOfSecurity = prfBitsOfSecurity;
            this.algorithmName = algorithmName;
            this.purpose = purpose;
        }

        public int bitsOfSecurity()
        {
            if (purpose == CryptoServicePurpose.PRF)
            {
                return prfBitsOfSecurity;
            }

            return bitsOfSecurity;
        }

        public String getServiceName()
        {
            return algorithmName;
        }

        public CryptoServicePurpose getPurpose()
        {
            return purpose;
        }

        public Object getParams()
        {
            return null;
        }
    }

    // Service Definitions
    private static class DefaultProperties
        implements CryptoServiceProperties
    {
        private final int bitsOfSecurity;
        private final String algorithmName;
        private final CryptoServicePurpose purpose;

        public DefaultProperties(int bitsOfSecurity, String algorithmName, CryptoServicePurpose purpose)
        {
            this.bitsOfSecurity = bitsOfSecurity;
            this.algorithmName = algorithmName;
            this.purpose = purpose;
        }

        public int bitsOfSecurity()
        {
            return bitsOfSecurity;
        }

        public String getServiceName()
        {
            return algorithmName;
        }

        public CryptoServicePurpose getPurpose()
        {
            return purpose;
        }

        public Object getParams()
        {
            return null;
        }
    }
}
