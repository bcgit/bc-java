package org.bouncycastle.jcajce.provider.digest;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

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

    static public class DigestSHAKE
        extends BCMessageDigest
        implements Cloneable
    {
        public DigestSHAKE(int type, int size)
        {
            super(new SHAKEDigest(type), size);
        }

        public byte[] engineDigest()
        {
            byte[]  digestBytes = new byte[digestSize];

            ((Xof)digest).doFinal(digestBytes, 0, digestSize);
    
            return digestBytes;
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            BCMessageDigest d = (BCMessageDigest)super.clone();
            d.digest = new SHAKEDigest((SHAKEDigest)digest);

            return d;
        }
    }

    public static class HashMacSHA3
        extends BaseMac
    {
        public HashMacSHA3(int size)
        {
            super(new HMac(new SHA3Digest(size)));
        }
    }

    public static class KeyGeneratorSHA3
        extends BaseKeyGenerator
    {
        public KeyGeneratorSHA3(int size)
        {
            super("HMACSHA3-" + size, size, new CipherKeyGenerator());
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

    static public class DigestShake128_256
        extends DigestSHAKE
    {
        public DigestShake128_256()
        {
            super(128, 256);
        }
    }

    static public class DigestShake256_512
        extends DigestSHAKE
    {
        public DigestShake256_512()
        {
            super(256, 512);
        }
    }

    static public class HashMac224
        extends HashMacSHA3
    {
        public HashMac224()
        {
            super(224);
        }
    }

    static public class HashMac256
        extends HashMacSHA3
    {
        public HashMac256()
        {
            super(256);
        }
    }

    static public class HashMac384
        extends HashMacSHA3
    {
        public HashMac384()
        {
            super(384);
        }
    }

    static public class HashMac512
        extends HashMacSHA3
    {
        public HashMac512()
        {
            super(512);
        }
    }

    static public class KeyGenerator224
        extends KeyGeneratorSHA3
    {
        public KeyGenerator224()
        {
            super(224);
        }
    }

    static public class KeyGenerator256
        extends KeyGeneratorSHA3
    {
        public KeyGenerator256()
        {
            super(256);
        }
    }

    static public class KeyGenerator384
        extends KeyGeneratorSHA3
    {
        public KeyGenerator384()
        {
            super(384);
        }
    }

    static public class KeyGenerator512
        extends KeyGeneratorSHA3
    {
        public KeyGenerator512()
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
            provider.addAlgorithm("MessageDigest.SHAKE256-512", PREFIX + "$DigestShake256_512");
            provider.addAlgorithm("MessageDigest.SHAKE128-256", PREFIX + "$DigestShake128_256");
            provider.addAlgorithm("MessageDigest", NISTObjectIdentifiers.id_shake256, PREFIX + "$DigestShake256_512");
            provider.addAlgorithm("MessageDigest", NISTObjectIdentifiers.id_shake128, PREFIX + "$DigestShake128_256");
            provider.addAlgorithm("Alg.Alias.MessageDigest.SHAKE256", "SHAKE256-512");
            provider.addAlgorithm("Alg.Alias.MessageDigest.SHAKE128", "SHAKE128-256");

            addHMACAlgorithm(provider, "SHA3-224", PREFIX + "$HashMac224",  PREFIX + "$KeyGenerator224");
            addHMACAlias(provider, "SHA3-224", NISTObjectIdentifiers.id_hmacWithSHA3_224);

            addHMACAlgorithm(provider, "SHA3-256", PREFIX + "$HashMac256",  PREFIX + "$KeyGenerator256");
            addHMACAlias(provider, "SHA3-256", NISTObjectIdentifiers.id_hmacWithSHA3_256);

            addHMACAlgorithm(provider, "SHA3-384", PREFIX + "$HashMac384",  PREFIX + "$KeyGenerator384");
            addHMACAlias(provider, "SHA3-384", NISTObjectIdentifiers.id_hmacWithSHA3_384);

            addHMACAlgorithm(provider, "SHA3-512", PREFIX + "$HashMac512",  PREFIX + "$KeyGenerator512");
            addHMACAlias(provider, "SHA3-512", NISTObjectIdentifiers.id_hmacWithSHA3_512);
        }
    }
}
