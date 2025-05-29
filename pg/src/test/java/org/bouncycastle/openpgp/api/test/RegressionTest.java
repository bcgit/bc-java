package org.bouncycastle.openpgp.api.test;

import java.security.Security;

import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[] tests = {
        new ChangeKeyPassphraseTest(),
        new DoubleBufferedInputStreamTest(),
        new OpenPGPCertificateTest(),
        new OpenPGPDetachedSignatureProcessorTest(),
        new OpenPGPKeyEditorTest(),
        new OpenPGPKeyReaderTest(),
        new OpenPGPMessageGeneratorTest(),
        new OpenPGPMessageProcessorTest(),
        new OpenPGPV4KeyGenerationTest(),
        new OpenPGPV6KeyGeneratorTest(),
        new StaticV6OpenPGPMessageGeneratorTest(),
    };

    public static void main(String[] args)
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        SimpleTest.runTests(tests);
    }
}
