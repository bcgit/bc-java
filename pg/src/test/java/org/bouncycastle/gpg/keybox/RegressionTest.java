package org.bouncycastle.gpg.keybox;

import java.security.Security;

import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[] tests = {
        new KeyBoxByteBufferTest(),
        new CertificateBlobTest()
    };

    public static void main(String[] args)
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        SimpleTest.runTests(tests);
    }
}
