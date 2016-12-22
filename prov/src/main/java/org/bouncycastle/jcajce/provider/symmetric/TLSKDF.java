package org.bouncycastle.jcajce.provider.symmetric;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jcajce.spec.TLSKeyMaterialSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class TLSKDF
{
    public static class TLSKeyMaterialFactory
        extends BaseSecretKeyFactory
    {
        protected TLSKeyMaterialFactory(String algName)
        {
            super(algName, null);
        }
    }

    public static final class TLS10
        extends TLSKeyMaterialFactory
    {
        public TLS10()
        {
            super("TLS10KDF");
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
        throws InvalidKeySpecException
        {
            if (keySpec instanceof TLSKeyMaterialSpec)
            {
                return new SecretKeySpec(PRF_legacy((TLSKeyMaterialSpec)keySpec), algName);
            }

            throw new InvalidKeySpecException("Invalid KeySpec");
        }
    }

    public static final class TLS11
        extends TLSKeyMaterialFactory
    {
        public TLS11()
        {
            super("TLS11KDF");
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
        throws InvalidKeySpecException
        {
            if (keySpec instanceof TLSKeyMaterialSpec)
            {
                return new SecretKeySpec(PRF_legacy((TLSKeyMaterialSpec)keySpec), algName);
            }

            throw new InvalidKeySpecException("Invalid KeySpec");
        }
    }

    private static byte[] PRF_legacy(TLSKeyMaterialSpec parameters)
    {
        Mac md5Hmac = new HMac(DigestFactory.createMD5());
        Mac sha1HMac = new HMac(DigestFactory.createSHA1());

        byte[] label = Strings.toByteArray(parameters.getLabel());
        byte[] labelSeed = Arrays.concatenate(label, parameters.getSeed());
        byte[] secret = parameters.getSecret();

        int s_half = (secret.length + 1) / 2;
        byte[] s1 = new byte[s_half];
        byte[] s2 = new byte[s_half];
        System.arraycopy(secret, 0, s1, 0, s_half);
        System.arraycopy(secret, secret.length - s_half, s2, 0, s_half);

        int size = parameters.getLength();
        byte[] b1 = new byte[size];
        byte[] b2 = new byte[size];

        hmac_hash(md5Hmac, s1, labelSeed, b1);
        hmac_hash(sha1HMac, s2, labelSeed, b2);

        for (int i = 0; i < size; i++)
        {
            b1[i] ^= b2[i];
        }
        return b1;
    }

    public static class TLS12
        extends TLSKeyMaterialFactory
    {
        private final Mac prf;

        protected TLS12(String algName, Mac prf)
        {
            super(algName);
            this.prf = prf;
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
        throws InvalidKeySpecException
        {
            if (keySpec instanceof TLSKeyMaterialSpec)
            {
                return new SecretKeySpec(PRF((TLSKeyMaterialSpec)keySpec, prf), algName);
            }

            throw new InvalidKeySpecException("Invalid KeySpec");
        }

        private byte[] PRF(TLSKeyMaterialSpec parameters, Mac prf)
        {
            byte[] label = Strings.toByteArray(parameters.getLabel());
            byte[] labelSeed = Arrays.concatenate(label, parameters.getSeed());
            byte[] secret = parameters.getSecret();

            byte[] buf = new byte[parameters.getLength()];

            hmac_hash(prf, secret, labelSeed, buf);

            return buf;
        }
    }

    public static final class TLS12withSHA256
        extends TLS12
    {
        public TLS12withSHA256()
        {
            super("TLS12withSHA256KDF", new HMac(new SHA256Digest()));
        }
    }

    public static final class TLS12withSHA384
        extends TLS12
    {
        public TLS12withSHA384()
        {
            super("TLS12withSHA384KDF", new HMac(new SHA384Digest()));
        }
    }

    public static final class TLS12withSHA512
        extends TLS12
    {
        public TLS12withSHA512()
        {
            super("TLS12withSHA512KDF", new HMac(new SHA512Digest()));
        }
    }

    private static void hmac_hash(Mac mac, byte[] secret, byte[] seed, byte[] out)
    {
        mac.init(new KeyParameter(secret));
        byte[] a = seed;
        int size = mac.getMacSize();
        int iterations = (out.length + size - 1) / size;
        byte[] buf = new byte[mac.getMacSize()];
        byte[] buf2 = new byte[mac.getMacSize()];
        for (int i = 0; i < iterations; i++)
        {
            mac.update(a, 0, a.length);
            mac.doFinal(buf, 0);
            a = buf;
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(buf2, 0);
            System.arraycopy(buf2, 0, out, (size * i), Math.min(size, out.length - (size * i)));
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = TLSKDF.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("SecretKeyFactory.TLS10KDF", PREFIX + "$TLS10");
            provider.addAlgorithm("SecretKeyFactory.TLS11KDF", PREFIX + "$TLS11");
            provider.addAlgorithm("SecretKeyFactory.TLS12WITHSHA256KDF", PREFIX + "$TLS12withSHA256");
            provider.addAlgorithm("SecretKeyFactory.TLS12WITHSHA384KDF", PREFIX + "$TLS12withSHA384");
            provider.addAlgorithm("SecretKeyFactory.TLS12WITHSHA512KDF", PREFIX + "$TLS12withSHA512");
        }
    }
}
