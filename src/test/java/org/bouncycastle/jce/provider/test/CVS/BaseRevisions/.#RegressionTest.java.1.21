package org.bouncycastle.jce.provider.test;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class RegressionTest
{
    public static Test[]    tests = {
        new FIPSDESTest(),
        new DESedeTest(),
        new AESTest(),
        new CamelliaTest(),
        new SEEDTest(),
        new AESSICTest(),
        new GOST28147Test(),
        new PBETest(),
        new BlockCipherTest(),
        new MacTest(),
        new HMacTest(),
        new SealedTest(),
        new RSATest(),
        new DHTest(),
        new DSATest(),
        new ImplicitlyCaTest(),
        new ECNRTest(),
        new ECIESTest(),
        new ECDSA5Test(),
        new GOST3410Test(),
        new ElGamalTest(),
        new IESTest(),
        new SigTest(),
        new AttrCertTest(),
        new CertTest(),
        new PKCS10CertRequestTest(),
        new EncryptedPrivateKeyInfoTest(),
        new KeyStoreTest(),
        new PKCS12StoreTest(),
        new DigestTest(),
        new PSSTest(),
        new WrapTest(),
        new DoFinalTest(),
        new CipherStreamTest(),
        new NamedCurveTest(),
        new PKIXTest(),
        new NetscapeCertRequestTest(),
        new X509StoreTest(),
        new X509StreamParserTest(),
        new X509CertificatePairTest(),
        new CertPathTest(),
        new CertStoreTest(),
        new CertPathValidatorTest(),
        new CertPathBuilderTest(),
        new ECEncodingTest(),
        new AlgorithmParametersTest(),
        new NISTCertPathTest(),
        new PKIXPolicyMappingTest(),
        new SlotTwoTest(),
        new PKIXNameConstraintsTest(),
        new MultiCertStoreTest(),
        new NoekeonTest(),
        new AttrCertSelectorTest(),
        new SerialisationTest(),
        new SigNameTest(),
        new MQVTest(),
        new CMacTest(),
        new DSTU4145Test(),
        new CRL5Test()
    };

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("Testing " + Security.getProvider("BC").getInfo() + " version: " + Security.getProvider("BC").getVersion());
        
        for (int i = 0; i != tests.length; i++)
        {
            TestResult  result = tests[i].perform();
            
            if (result.getException() != null)
            {
                result.getException().printStackTrace();
            }
            
            System.out.println(result);
        }
    }
}

