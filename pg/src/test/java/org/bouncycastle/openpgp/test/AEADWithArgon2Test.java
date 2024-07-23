package org.bouncycastle.openpgp.test;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;

public class AEADWithArgon2Test
    extends TestCase
{
    public void testAEADProtectedPGPSecretKey()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        AEADProtectedPGPSecretKeyTest test = new AEADProtectedPGPSecretKeyTest();

        SimpleTestResult result = (SimpleTestResult)test.perform();

        if (!result.isSuccessful())
        {
            fail(test.getClass().getName() + " " + result.toString());
        }
    }
}
