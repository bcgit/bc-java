package org.bouncycastle.jcajce.provider.digest;

import org.bouncycastle.crypto.digests.AsconCXof128;
import org.bouncycastle.crypto.digests.AsconHash256;
import org.bouncycastle.crypto.digests.AsconXof128;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

/**
 * The NIST SP 800-232 Ascon hash functions as JCA MessageDigests: Ascon-Hash256, and the XOFs
 * Ascon-XOF128 and Ascon-CXOF128 with a 256 bit output. ASCON-CXOF128 is registered with an
 * empty customization string; the light-weight {@link AsconCXof128} takes one.
 */
public class Ascon
{
    private Ascon()
    {
    }

    static public class Hash256
        extends BCMessageDigest
    {
        public Hash256()
        {
            super(new AsconHash256());
        }
    }

    static public class Xof128
        extends BCMessageDigest
    {
        public Xof128()
        {
            super(new AsconXof128());
        }
    }

    static public class CXof128
        extends BCMessageDigest
    {
        public CXof128()
        {
            super(new AsconCXof128());
        }
    }

    public static class Mappings
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = Ascon.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("MessageDigest.ASCON-HASH256", PREFIX + "$Hash256");
            provider.addAlgorithm("MessageDigest.ASCON-XOF128", PREFIX + "$Xof128");
            provider.addAlgorithm("MessageDigest.ASCON-CXOF128", PREFIX + "$CXof128");
        }
    }
}
