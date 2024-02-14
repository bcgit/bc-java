package org.bouncycastle.openpgp.test;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

public class OperatorBcTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OperatorBcTest());
    }

    @Override
    public String getName()
    {
        return "OperatorBcTest";
    }

    @Override
    public void performTest()
        throws Exception
    {

    }


}
