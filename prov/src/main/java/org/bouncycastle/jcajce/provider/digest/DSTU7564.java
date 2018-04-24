package org.bouncycastle.jcajce.provider.digest;

import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.digests.DSTU7564Digest;
import org.bouncycastle.crypto.macs.DSTU7564Mac;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

public class DSTU7564
{
    private DSTU7564()
    {

    }

    static public class DigestDSTU7564
        extends BCMessageDigest
        implements Cloneable
    {
        public DigestDSTU7564(int size)
        {
            super(new DSTU7564Digest(size));
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            BCMessageDigest d = (BCMessageDigest)super.clone();
            d.digest = new DSTU7564Digest((DSTU7564Digest)digest);

            return d;
        }
    }

    static public class Digest256
        extends DigestDSTU7564
    {
        public Digest256()
        {
            super(256);
        }
    }

    static public class Digest384
        extends DigestDSTU7564
    {
        public Digest384()
        {
            super(384);
        }
    }

    static public class Digest512
        extends DigestDSTU7564
    {
        public Digest512()
        {
            super(512);
        }
    }

    public static class HashMac256
        extends BaseMac
    {
        public HashMac256()
        {
            super(new DSTU7564Mac(256));
        }
    }

    public static class HashMac384
        extends BaseMac
    {
        public HashMac384()
        {
            super(new DSTU7564Mac(384));
        }
    }

    public static class HashMac512
        extends BaseMac
    {
        public HashMac512()
        {
            super(new DSTU7564Mac(512));
        }
    }

    public static class KeyGenerator256
        extends BaseKeyGenerator
    {
        public KeyGenerator256()
        {
            super("HMACDSTU7564-256", 256, new CipherKeyGenerator());
        }
    }

    public static class KeyGenerator384
        extends BaseKeyGenerator
    {
        public KeyGenerator384()
        {
            super("HMACDSTU7564-384", 384, new CipherKeyGenerator());
        }
    }

    public static class KeyGenerator512
        extends BaseKeyGenerator
    {
        public KeyGenerator512()
        {
            super("HMACDSTU7564-512", 512, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = DSTU7564.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("MessageDigest.DSTU7564-256", PREFIX + "$Digest256");
            provider.addAlgorithm("MessageDigest.DSTU7564-384", PREFIX + "$Digest384");
            provider.addAlgorithm("MessageDigest.DSTU7564-512", PREFIX + "$Digest512");

            provider.addAlgorithm("MessageDigest", UAObjectIdentifiers.dstu7564digest_256, PREFIX + "$Digest256");
            provider.addAlgorithm("MessageDigest", UAObjectIdentifiers.dstu7564digest_384, PREFIX + "$Digest384");
            provider.addAlgorithm("MessageDigest", UAObjectIdentifiers.dstu7564digest_512, PREFIX + "$Digest512");

            addHMACAlgorithm(provider, "DSTU7564-256", PREFIX + "$HashMac256", PREFIX + "$KeyGenerator256");
            addHMACAlgorithm(provider, "DSTU7564-384", PREFIX + "$HashMac384", PREFIX + "$KeyGenerator384");
            addHMACAlgorithm(provider, "DSTU7564-512", PREFIX + "$HashMac512", PREFIX + "$KeyGenerator512");

            addHMACAlias(provider, "DSTU7564-256", UAObjectIdentifiers.dstu7564mac_256);
            addHMACAlias(provider, "DSTU7564-384", UAObjectIdentifiers.dstu7564mac_384);
            addHMACAlias(provider, "DSTU7564-512", UAObjectIdentifiers.dstu7564mac_512);
        }
    }
}
