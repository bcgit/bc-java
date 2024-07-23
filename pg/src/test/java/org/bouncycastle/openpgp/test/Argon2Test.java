package org.bouncycastle.openpgp.test;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;

public class Argon2Test
    extends TestCase
{
    public void testArgon2()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        Argon2S2KTest test = new Argon2S2KTest();

        SimpleTestResult result = (SimpleTestResult)test.perform();

        if (!result.isSuccessful())
        {
            fail(test.getClass().getName() + " " + result.toString());
        }
    }
}
