package org.bouncycastle.openpgp.api.test;

import java.security.Security;

import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[] tests = {
        new ChangeKeyPassphraseTest(),
        new JceExternalPublicKeyDataDecryptorFactoryBuilderTest(),
        new OpenPGPConfiguredPolicyTest(),
        new OpenPGPDecompressionLimitTest(),
        new OpenPGPCertificateTest(),
        new OpenPGPDetachedSignatureProcessorTest(),
        new OpenPGPDocumentSignatureExpiryTest(),
        new OpenPGPDocumentSignatureTypeTest(),
        new OpenPGPKeyEditorTest(),
        new OpenPGPKeyReaderTest(),
        new OpenPGPMessageGeneratorTest(),
        new OpenPGPMessageProcessorTest(),
        new OpenPGPMissingCrossCertificationTest(),
        new OpenPGPPrimaryKeyExpiryTest(),
        new OpenPGPSubkeyExpiryForgeryTest(),
        new OpenPGPUnverifiedSelfSignatureTest(),
        new OpenPGPThirdPartyCertificationAuthorityTest(),
        new OpenPGPV4KeyGenerationTest(),
        new OpenPGPV6DirectKeySignatureTest(),
        new OpenPGPV6KeyGeneratorTest(),
        new StaticV6OpenPGPMessageGeneratorTest(),
    };

    public static void main(String[] args)
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        SimpleTest.runTests(tests);
    }
}
