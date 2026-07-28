package org.bouncycastle.jce.provider.test;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

// NOTE: jdk1.3 overlay. AEADTest, AlgorithmParametersTest, CertLocaleTest, ChaCha20Poly1305Test,
// XChaCha20Poly1305Test, CRL5Test, DetDSATest, DHIESTest, DSTU4145Test, DSTU7624Test, ECDSA5Test,
// ECEncodingTest, ECIESTest, GOST3410KeyPairTest, MQVTest, NamedCurveTest, PBETest,
// PKCS12SecretKeyStoreTest, PKIXNameConstraintsTest, PQCDHTest, PSSTest, SM9KEMTest,
// SM9SignatureTest and XIESTest are all excluded from the jdk1.3 build (post-1.3 JDK APIs,
// ant/jdk13.xml) so their references are dropped here.
public class RegressionTest
{
    public static Test[] tests = {
        new AESSICTest(),
        new AESTest(),
        new ARIATest(),
        new BCFKSStoreTest(),
        new BlockCipherTest(),
        new CamelliaTest(),
        new CertPathBuilderTest(),
        new CertPathTest(),
        new CertPathValidatorTest(),
        new CertStoreTest(),
        new CertTest(),
        new CertUniqueIDTest(),
        new CipherStreamTest(),
        new CipherStreamTest2(),
        new CMacTest(),
        new DESedeTest(),
        new DHTest(),
        new DigestTest(),
        new DoFinalTest(),
        new DRBGTest(),
        new DSATest(),
        new ECIESVectorTest(),
        new ECNRTest(),
        new EdECTest(),
        new ElGamalTest(),
        new EncryptedPrivateKeyInfoTest(),
        new FIPSDESTest(),
        new GMacTest(),
        new GOST28147Test(),
        new GOST3410Test(),
        new GOST3412Test(),
        new HMacTest(),
        new IESTest(),
        new ImplicitlyCaTest(),
        new KeccakTest(),
        new Argon2KeyFactoryTest(),
        new KeyStoreTest(),
        new MacTest(),
        new MalformedKeyInfoTest(),
        new MessageDigestUtilsTest(),
        new MultiCertStoreTest(),
        new NetscapeCertRequestTest(),
        new NISTCertPathTest(),
        new NoekeonTest(),
        new OCBTest(),
        new OpenSSHSpecTests(),
        new PKCS10CertRequestTest(),
        new PKCS12StorePBETest(),
        new PKCS12StoreTest(),
        new PKIXPolicyMappingTest(),
        new PKIXTest(),
        new Poly1305Test(),
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
        new SM2KeyExchangeTest(),
        new SM2SignatureTest(),
        new SM4Test(),
        new SM9CipherTest(),
        new ThreefishTest(),
        new TLSKDFTest(),
        new WrapTest(),
        new X509CertificatePairTest(),
        new X509StreamParserTest(),
        new XOFTest(),
        new ZucTest(),
    };

    public static void main(String[] args)
    {
        System.setProperty("org.bouncycastle.bks.enable_v1", "true");

        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        System.out.println("Testing " + Security.getProvider("BC").getInfo() + " version: " + Security.getProvider("BC").getVersion());

        SimpleTest.runTests(tests);
    }
}
