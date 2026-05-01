package org.bouncycastle.jce.provider.test;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[] tests = {
        new AEADTest(),
        new AESSICTest(),
        new AESTest(),
        new AlgorithmParametersTest(),
        new ARIATest(),
        new BCFKSStoreTest(),
        new BlockCipherTest(),
        new CamelliaTest(),
        new CertLocaleTest(),
        new CertPathBuilderTest(),
        new CertPathTest(),
        new CertPathValidatorTest(),
        new CertStoreTest(),
        new CertTest(),
        new CertUniqueIDTest(),
        new ChaCha20Poly1305Test(),
        new CipherStreamTest(),
        new CipherStreamTest2(),
        new CMacTest(),
        new CRL5Test(),
        new DESedeTest(),
        new DetDSATest(),
        new DHIESTest(),
        new DHTest(),
        new DigestTest(),
        new DoFinalTest(),
        new DRBGTest(),
        new DSATest(),
        new DSTU4145Test(),
        new DSTU7624Test(),
        new ECDSA5Test(),
        new ECEncodingTest(),
        new ECIESTest(),
        new ECIESVectorTest(),
        new ECNRTest(),
        new EdECTest(),
        new ElGamalTest(),
        new EncryptedPrivateKeyInfoTest(),
        new FIPSDESTest(),
        new GMacTest(),
        new GOST28147Test(),
        new GOST3410KeyPairTest(),
        new GOST3410Test(),
        new GOST3412Test(),
        new HMacTest(),
        new IESTest(),
        new ImplicitlyCaTest(),
        new KeccakTest(),
        new KeyStoreTest(),
        new MacTest(),
        new MQVTest(),
        new MultiCertStoreTest(),
        new NamedCurveTest(),
        new NetscapeCertRequestTest(),
        new NISTCertPathTest(),
        new NoekeonTest(),
        new OCBTest(),
        new OpenSSHSpecTests(),
        new PBETest(),
        new PKCS10CertRequestTest(),
        new PKCS12StorePBETest(),
        new PKCS12StoreTest(),
        new PKIXNameConstraintsTest(),
        new PKIXPolicyMappingTest(),
        new PKIXTest(),
        new Poly1305Test(),
        new PQCDHTest(),
        new PSSTest(),
        new RSATest(),
        new SealedTest(),
        new SEEDTest(),
        new SerialisationTest(),
        new Shacal2Test(),
        new SigNameTest(),
        new SignatureTest(),
        new SigTest(),
        new SipHash128Test(),
        new SipHashTest(),
        new SkeinTest(),
        new SlotTwoTest(),
        new SM2CipherTest(),
        new SM2SignatureTest(),
        new SM4Test(),
        new ThreefishTest(),
        new TLSKDFTest(),
        new WrapTest(),
        new X509CertificatePairTest(),
        new X509StreamParserTest(),
        new XIESTest(),
        new XOFTest(),
        new ZucTest(),
    };

    public static void main(String[] args)
    {
        System.setProperty("org.bouncycastle.bks.enable_v1", "true");

        Security.addProvider(new BouncyCastleProvider());

        System.out.println("Testing " + Security.getProvider("BC").getInfo() + " version: " + Security.getProvider("BC").getVersion());

        SimpleTest.runTests(tests);
    }
}
