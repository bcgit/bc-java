package org.bouncycastle.jce.provider.test;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new FIPSDESTest(),
        new DESedeTest(),
        new AESTest(),
        new AEADTest(),
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
        new DHIESTest(),
        new DSATest(),
        new ImplicitlyCaTest(),
        new ECNRTest(),
        new ECIESTest(),
        new ECIESVectorTest(),
        new ECDSA5Test(),
        new GOST3410Test(),
        new ElGamalTest(),
        new IESTest(),
        new SigTest(),
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
        new CipherStreamTest2(),
        new NamedCurveTest(),
        new PKIXTest(),
        new NetscapeCertRequestTest(),
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
        new SerialisationTest(),
        new SigNameTest(),
        new MQVTest(),
        new CMacTest(),
        new GMacTest(),
        new OCBTest(),
        new DSTU4145Test(),
        new CRL5Test(),
        new Poly1305Test(),
        new SipHashTest(),
        new KeccakTest(),
        new SkeinTest(),
        new Shacal2Test(),
        new DetDSATest(),
        new ThreefishTest(),
        new SM2SignatureTest(),
        new SM4Test(),
        new TLSKDFTest(),
        new BCFKSStoreTest(),
        new DSTU7624Test(),
        new GOST3412Test(),
        new GOST3410KeyPairTest(),
        new EdECTest(),
        new OpenSSHSpecTests(),
        new SM2CipherTest(),
        new ZucTest(),
        new ChaCha20Poly1305Test(),
        new SipHash128Test()
    };

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("Testing " + Security.getProvider("BC").getInfo() + " version: " + Security.getProvider("BC").getVersion());

        SimpleTest.runTests(tests);
    }
}
