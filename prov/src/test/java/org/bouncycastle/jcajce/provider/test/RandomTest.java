package org.bouncycastle.jcajce.provider.test;

import java.security.SecureRandom;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RandomTest
    extends TestCase
{
    public void testCheckRandom()
        throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DEFAULT", new BouncyCastleProvider());

        byte[] rng = new byte[20];

        random.nextBytes(rng);

        Assert.assertTrue(checkNonConstant(rng));
    }

    public void testCheckNonceIVRandom()
        throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("NONCEANDIV", new BouncyCastleProvider());

        byte[] rng = new byte[20];

        random.nextBytes(rng);

        Assert.assertTrue(checkNonConstant(rng));
    }

    public void testCheckEntropyProperty()
        throws Exception
    {
        System.setProperty("org.bouncycastle.drbg.entropysource", "org.bouncycastle.jcajce.provider.test.RandomTest$MyEntropySourceProvider");

        SecureRandom random = SecureRandom.getInstance("DEFAULT", new BouncyCastleProvider());

        byte[] rng = new byte[20];

        random.nextBytes(rng);

        Assert.assertTrue(checkNonConstant(rng));
        Assert.assertTrue(MyEntropySourceProvider.isCalled);

        System.clearProperty("org.bouncycastle.drbg.entropysource");
    }

    private boolean checkNonConstant(byte[] data)
    {
        for (int i = 1; i != data.length; i++)
        {
            if (data[i] != data[i - 1])
            {
                return true;
            }
        }

        return false;
    }

    public static class MyEntropySourceProvider
        implements EntropySourceProvider
    {
        public static boolean isCalled;

        public MyEntropySourceProvider()
        {

        }

        public EntropySource get(final int bitsRequired)
        {
            final SecureRandom random = new SecureRandom();

            return new EntropySource()
            {
                public boolean isPredictionResistant()
                {
                    return false;
                }

                public byte[] getEntropy()
                {
                    byte[] rv = new byte[bitsRequired / 8];

                    isCalled = true;
                    random.nextBytes(rv);

                    return rv;
                }

                public int entropySize()
                {
                    return bitsRequired;
                }
            };
        }
    }
}
