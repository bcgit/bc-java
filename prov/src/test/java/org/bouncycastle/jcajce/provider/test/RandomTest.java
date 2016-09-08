package org.bouncycastle.jcajce.provider.test;

import java.security.SecureRandom;

import junit.framework.Assert;
import junit.framework.TestCase;
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
}
