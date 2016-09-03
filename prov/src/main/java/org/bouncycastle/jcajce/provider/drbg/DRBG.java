package org.bouncycastle.jcajce.provider.drbg;

import java.lang.reflect.Constructor;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

public class DRBG
{
    private static final String PREFIX = DRBG.class.getName();

    private static SecureRandom secureRandom = new SecureRandom();

    public static class Default
        extends SecureRandomSpi
    {
        private SecureRandom random = new SP800SecureRandomBuilder(secureRandom, true)
            .setPersonalizationString(generateDefaultPersonalizationString())
            .buildHash(new SHA512Digest(), secureRandom.generateSeed(32), true);

        @Override
        protected void engineSetSeed(byte[] bytes)
        {
            random.setSeed(bytes);
        }

        @Override
        protected void engineNextBytes(byte[] bytes)
        {
            random.nextBytes(bytes);
        }

        @Override
        protected byte[] engineGenerateSeed(int numBytes)
        {
            return secureRandom.generateSeed(numBytes);
        }
    }

    public static class NonceAndIV
        extends SecureRandomSpi
    {
        private SecureRandom random = new SP800SecureRandomBuilder(secureRandom, true)
            .setPersonalizationString(generateNonceIVPersonalizationString())
            .buildHash(new SHA512Digest(), secureRandom.generateSeed(32), false);

        @Override
        protected void engineSetSeed(byte[] bytes)
        {
            random.setSeed(bytes);
        }

        @Override
        protected void engineNextBytes(byte[] bytes)
        {
            random.nextBytes(bytes);
        }

        @Override
        protected byte[] engineGenerateSeed(int numBytes)
        {
            return secureRandom.generateSeed(numBytes);
        }
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("SecureRandom.DEFAULT", PREFIX + "$Default");
            provider.addAlgorithm("SecureRandom.NONCEANDIV", PREFIX + "$NonceAndIV");
        }
    }

    private static byte[] generateDefaultPersonalizationString()
    {
        return Arrays.concatenate(Strings.toByteArray("Default"), Strings.toUTF8ByteArray(getVIMID()),
            Pack.longToBigEndian(Thread.currentThread().getId()), Pack.longToBigEndian(System.currentTimeMillis()));
    }

    private static byte[] generateNonceIVPersonalizationString()
    {
        return Arrays.concatenate(Strings.toByteArray("Default"), Strings.toUTF8ByteArray(getVIMID()),
            Pack.longToLittleEndian(Thread.currentThread().getId()), Pack.longToLittleEndian(System.currentTimeMillis()));
    }

    private static final Constructor vimIDConstructor;

    static
    {
        Class vimIDClass = lookup("java.rmi.dgc.VMID");
        if (vimIDClass != null)
        {
            vimIDConstructor = findConstructor(vimIDClass);
        }
        else
        {
            vimIDConstructor = null;
        }
    }

    private static Class lookup(String className)
    {
        try
        {
            Class def = DRBG.class.getClassLoader().loadClass(className);

            return def;
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private static Constructor findConstructor(Class clazz)
    {
        try
        {
            return clazz.getConstructor();
        }
        catch (Exception e)
        {
            return null;
        }
    }

    static String getVIMID()
    {
        if (vimIDConstructor != null)
        {
            Object vimID = null;
            try
            {
                vimID = vimIDConstructor.newInstance();
            }
            catch (Exception i)
            {
                // might happen, fall through if it does
            }
            if (vimID != null)
            {
                return vimID.toString();
            }
        }

        return "No VIM ID"; // TODO: maybe there is a system property we can use here.
    }
}
