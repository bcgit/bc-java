package org.bouncycastle.jcajce.provider.digest;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

public class SHA3
{
    private SHA3()
    {

    }

    static public class DigestSHA3
        extends BCMessageDigest
        implements Cloneable
    {
        public DigestSHA3(int size)
        {
            super(new SHA3Digest(size));
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            BCMessageDigest d = (BCMessageDigest)super.clone();
            d.digest = new SHA3Digest((SHA3Digest)digest);

            return d;
        }
    }

    static public class Digest224
        extends DigestSHA3
    {
        public Digest224()
        {
            super(224);
        }
    }

    static public class Digest256
        extends DigestSHA3
    {
        public Digest256()
        {
            super(256);
        }
    }

    static public class Digest384
        extends DigestSHA3
    {
        public Digest384()
        {
            super(384);
        }
    }

    static public class Digest512
        extends DigestSHA3
    {
        public Digest512()
        {
            super(512);
        }
    }

    public static class Mappings
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = SHA3.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("MessageDigest.SHA3-224", PREFIX + "$Digest224");
            provider.addAlgorithm("MessageDigest.SHA3-256", PREFIX + "$Digest256");
            provider.addAlgorithm("MessageDigest.SHA3-384", PREFIX + "$Digest384");
            provider.addAlgorithm("MessageDigest.SHA3-512", PREFIX + "$Digest512");
            provider.addAlgorithm("MessageDigest", NISTObjectIdentifiers.id_sha3_224, PREFIX + "$Digest224");
            provider.addAlgorithm("MessageDigest", NISTObjectIdentifiers.id_sha3_256, PREFIX + "$Digest256");
            provider.addAlgorithm("MessageDigest", NISTObjectIdentifiers.id_sha3_384, PREFIX + "$Digest384");
            provider.addAlgorithm("MessageDigest", NISTObjectIdentifiers.id_sha3_512, PREFIX + "$Digest512");
        }
    }
}
