package org.bouncycastle.jcajce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.RFC3211WrapEngine;
import org.bouncycastle.crypto.generators.DESKeyGenerator;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.macs.CFBBlockCipherMac;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class DES
{
    private DES()
    {
    }

    static public class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new DESEngine());
        }
    }

    static public class CBC
        extends BaseBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new DESEngine()), 64);
        }
    }

    /**
     * DES   CFB8
     */
    public static class DESCFB8
        extends BaseMac
    {
        public DESCFB8()
        {
            super(new CFBBlockCipherMac(new DESEngine()));
        }
    }

    /**
     * DES64
     */
    public static class DES64
        extends BaseMac
    {
        public DES64()
        {
            super(new CBCBlockCipherMac(new DESEngine(), 64));
        }
    }

    /**
     * DES64with7816-4Padding
     */
    public static class DES64with7816d4
        extends BaseMac
    {
        public DES64with7816d4()
        {
            super(new CBCBlockCipherMac(new DESEngine(), 64, new ISO7816d4Padding()));
        }
    }
    
    public static class CBCMAC
        extends BaseMac
    {
        public CBCMAC()
        {
            super(new CBCBlockCipherMac(new DESEngine()));
        }
    }

    static public class CMAC
        extends BaseMac
    {
        public CMAC()
        {
            super(new CMac(new DESEngine()));
        }
    }

    public static class RFC3211
        extends BaseWrapCipher
    {
        public RFC3211()
        {
            super(new RFC3211WrapEngine(new DESEngine()), 8);
        }
    }

    public static class AlgParamGen
        extends BaseAlgorithmParameterGenerator
    {
        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom            random)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for DES parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            byte[]  iv = new byte[8];

            if (random == null)
            {
                random = new SecureRandom();
            }

            random.nextBytes(iv);

            AlgorithmParameters params;

            try
            {
                params = AlgorithmParameters.getInstance("DES", BouncyCastleProvider.PROVIDER_NAME);
                params.init(new IvParameterSpec(iv));
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.getMessage());
            }

            return params;
        }
    }

  /**
     * DES - the default for this is to generate a key in
     * a-b-a format that's 24 bytes long but has 16 bytes of
     * key material (the first 8 bytes is repeated as the last
     * 8 bytes). If you give it a size, you'll get just what you
     * asked for.
     */
    public static class KeyGenerator
        extends BaseKeyGenerator
    {
        public KeyGenerator()
        {
            super("DES", 64, new DESKeyGenerator());
        }

        protected void engineInit(
            int             keySize,
            SecureRandom random)
        {
            super.engineInit(keySize, random);
        }

        protected SecretKey engineGenerateKey()
        {
            if (uninitialised)
            {
                engine.init(new KeyGenerationParameters(new SecureRandom(), defaultKeySize));
                uninitialised = false;
            }

            return new SecretKeySpec(engine.generateKey(), algName);
        }
    }

    static public class KeyFactory
        extends BaseSecretKeyFactory
    {
        public KeyFactory()
        {
            super("DES", null);
        }

        protected KeySpec engineGetKeySpec(
            SecretKey key,
            Class keySpec)
        throws InvalidKeySpecException
        {
            if (keySpec == null)
            {
                throw new InvalidKeySpecException("keySpec parameter is null");
            }
            if (key == null)
            {
                throw new InvalidKeySpecException("key parameter is null");
            }

            if (SecretKeySpec.class.isAssignableFrom(keySpec))
            {
                return new SecretKeySpec(key.getEncoded(), algName);
            }
            else if (DESKeySpec.class.isAssignableFrom(keySpec))
            {
                byte[]  bytes = key.getEncoded();

                try
                {
                    return new DESKeySpec(bytes);
                }
                catch (Exception e)
                {
                    throw new InvalidKeySpecException(e.toString());
                }
            }

            throw new InvalidKeySpecException("Invalid KeySpec");
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
        throws InvalidKeySpecException
        {
            if (keySpec instanceof DESKeySpec)
            {
                DESKeySpec desKeySpec = (DESKeySpec)keySpec;
                return new SecretKeySpec(desKeySpec.getKey(), "DES");
            }

            return super.engineGenerateSecret(keySpec);
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = DES.class.getName();
        private static final String PACKAGE = "org.bouncycastle.jcajce.provider.symmetric"; // JDK 1.2

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.DES", PREFIX + "$ECB");
            provider.addAlgorithm("Cipher." + OIWObjectIdentifiers.desCBC, PREFIX + "$CBC");

            addAlias(provider, OIWObjectIdentifiers.desCBC, "DES");

            provider.addAlgorithm("Cipher.DESRFC3211WRAP", PREFIX + "$RFC3211");

            provider.addAlgorithm("KeyGenerator.DES", PREFIX + "$KeyGenerator");

            provider.addAlgorithm("SecretKeyFactory.DES", PREFIX + "$KeyFactory");

            provider.addAlgorithm("Mac.DESCMAC", PREFIX + "$CMAC");
            provider.addAlgorithm("Mac.DESMAC", PREFIX + "$CBCMAC");
            provider.addAlgorithm("Alg.Alias.Mac.DES", "DESMAC");

            provider.addAlgorithm("Mac.DESMAC/CFB8", PREFIX + "$DESCFB8");
            provider.addAlgorithm("Alg.Alias.Mac.DES/CFB8", "DESMAC/CFB8");

            provider.addAlgorithm("Mac.DESMAC64", PREFIX + "$DES64");
            provider.addAlgorithm("Alg.Alias.Mac.DES64", "DESMAC64");

            provider.addAlgorithm("Mac.DESMAC64WITHISO7816-4PADDING", PREFIX + "$DES64with7816d4");
            provider.addAlgorithm("Alg.Alias.Mac.DES64WITHISO7816-4PADDING", "DESMAC64WITHISO7816-4PADDING");
            provider.addAlgorithm("Alg.Alias.Mac.DESISO9797ALG1MACWITHISO7816-4PADDING", "DESMAC64WITHISO7816-4PADDING");
            provider.addAlgorithm("Alg.Alias.Mac.DESISO9797ALG1WITHISO7816-4PADDING", "DESMAC64WITHISO7816-4PADDING");

            provider.addAlgorithm("AlgorithmParameters.DES", PACKAGE + ".util.IvAlgorithmParameters");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + OIWObjectIdentifiers.desCBC, "DES");

            provider.addAlgorithm("AlgorithmParameterGenerator.DES",  PREFIX + "$AlgParamGen");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + OIWObjectIdentifiers.desCBC, "DES");
        }

        private void addAlias(ConfigurableProvider provider, ASN1ObjectIdentifier oid, String name)
        {
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + oid.getId(), name);
            provider.addAlgorithm("Alg.Alias.KeyFactory." + oid.getId(), name);
        }
    }
}
