package org.bouncycastle.cert.test;

import java.security.GeneralSecurityException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

public class MLKEMCredentialsTest
    extends SimpleTest
{
    public String getName()
    {
        return "MLKEMCredentials";
    }

    public void performTest()
        throws Exception
    {
        checkSampleCredentials(SampleCredentials.ML_KEM_512, SampleCredentials.ML_DSA_44);
        checkSampleCredentials(SampleCredentials.ML_KEM_768, SampleCredentials.ML_DSA_65);
        checkSampleCredentials(SampleCredentials.ML_KEM_1024, SampleCredentials.ML_DSA_87);
    }

    private static void checkSampleCredentials(SampleCredentials subject, SampleCredentials issuer)
        throws GeneralSecurityException
    {
        subject.getCertificate().verify(issuer.getCertificate().getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new MLKEMCredentialsTest());
    }
}
