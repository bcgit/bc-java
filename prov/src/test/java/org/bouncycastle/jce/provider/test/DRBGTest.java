package org.bouncycastle.jce.provider.test;

import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

/**
 * This test needs to be run with -Djava.security.debug=provider
 */
public class DRBGTest
    extends SimpleTest
{
    public DRBGTest()
    {
    }
    
    public String getName()
    {
        return "DRBG";
    }

    public void performTest()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        SecureRandom.getInstance("DEFAULT", "BC");
    }

    public static void main(
        String[]    args)
    {
        runTest(new DRBGTest());
    }
}
