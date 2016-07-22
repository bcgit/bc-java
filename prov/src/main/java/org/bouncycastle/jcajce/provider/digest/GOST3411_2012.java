package org.bouncycastle.jcajce.provider.digest;

import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

public class GOST3411_2012 {

    private GOST3411_2012() {}

    static public class Digest256
            extends BCMessageDigest
            implements Cloneable
    {
        public Digest256()
        {
            super(new GOST3411_2012_256Digest());
        }

        public Object clone()
                throws CloneNotSupportedException
        {
            GOST3411_2012.Digest256 d = (GOST3411_2012.Digest256)super.clone();
            d.digest = new GOST3411_2012_256Digest((GOST3411_2012_256Digest)digest);

            return d;
        }
    }

    static public class Digest512
            extends BCMessageDigest
            implements Cloneable
    {
        public Digest512()
        {
            super(new GOST3411_2012_512Digest());
        }

        public Object clone()
                throws CloneNotSupportedException
        {
            GOST3411_2012.Digest512 d = (GOST3411_2012.Digest512)super.clone();
            d.digest = new GOST3411_2012_512Digest((GOST3411_2012_512Digest)digest);

            return d;
        }
    }

    public static class Mappings
            extends DigestAlgorithmProvider
    {
        public Mappings() {}

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("MessageDigest.GOST3411-2012-256", GOST3411_2012.Digest256.class.getName());
            provider.addAlgorithm("MessageDigest.GOST3411-2012-512", GOST3411_2012.Digest512.class.getName());
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411-2012.256", "GOST3411-2012-256");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411-2012.512", "GOST3411-2012-512");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411-2012_256", "GOST3411-2012-256");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411-2012_512", "GOST3411-2012-512");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411.2012-256", "GOST3411-2012-256");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411.2012-512", "GOST3411-2012-512");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411.2012.256", "GOST3411-2012-256");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411.2012.512", "GOST3411-2012-512");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411.2012_256", "GOST3411-2012-256");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411.2012_512", "GOST3411-2012-512");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411_2012-256", "GOST3411-2012-256");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411_2012-512", "GOST3411-2012-512");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411_2012.256", "GOST3411-2012-256");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411_2012.512", "GOST3411-2012-512");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411_2012_256", "GOST3411-2012-256");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST3411_2012_512", "GOST3411-2012-512");
        }
    }
}
