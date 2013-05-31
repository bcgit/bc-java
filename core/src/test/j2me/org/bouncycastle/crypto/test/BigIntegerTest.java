package org.bouncycastle.crypto.test;

import org.bouncycastle.util.test.*;

public class BigIntegerTest
{
    public static Test[]    tests = {
        new DHTest(),
        new ElGamalTest(),
        new DSATest(),
        new ECTest(),
        new ECIESTest(),
        new RSATest(),
        new ISO9796Test(),
        new OAEPTest(),
        new PSSTest(),
        new CTSTest(),
        new PKCS5Test(),
        new PKCS12Test()
	};

    public static void main(
        String[]    args)
    {
        for (int i = 0; i != tests.length; i++)
        {
            TestResult  result = tests[i].perform();
            System.out.println(result);
        }
    }
}

