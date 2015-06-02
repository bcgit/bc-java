package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Date;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.test.UncloseableOutputStream;

/**
 * GPG compatability test vectors
 */
public class DSA2Test
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    public void testK1024H160()
        throws Exception
    {
        doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-160-sign.gpg");
    }

    public void testK1024H224()
        throws Exception
    {
        doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-224-sign.gpg");
    }

    public void testK1024H256()
        throws Exception
    {
        doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-256-sign.gpg");
    }

    public void testK1024H384()
        throws Exception
    {
        doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-384-sign.gpg");
    }

    public void testK1024H512()
        throws Exception
    {
        doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-512-sign.gpg");
    }

    public void testK2048H224()
        throws Exception
    {
        doSigVerifyTest("DSA-2048-224.pub", "dsa-2048-224-sign.gpg");
    }

    public void testK3072H256()
        throws Exception
    {
        doSigVerifyTest("DSA-3072-256.pub", "dsa-3072-256-sign.gpg");
    }

    public void testK7680H384()
        throws Exception
    {
        doSigVerifyTest("DSA-7680-384.pub", "dsa-7680-384-sign.gpg");
    }

    public void testK15360H512()
        throws Exception
    {
        doSigVerifyTest("DSA-15360-512.pub", "dsa-15360-512-sign.gpg");
    }

    public void testGenerateK1024H224()
        throws Exception
    {
        doSigGenerateTest("DSA-1024-160.sec", "DSA-1024-160.pub", PGPUtil.SHA224);
    }

    public void testGenerateK1024H256()
        throws Exception
    {
        doSigGenerateTest("DSA-1024-160.sec", "DSA-1024-160.pub", PGPUtil.SHA256);
    }

    public void testGenerateK1024H384()
        throws Exception
    {
        doSigGenerateTest("DSA-1024-160.sec", "DSA-1024-160.pub", PGPUtil.SHA384);
    }

    public void testGenerateK1024H512()
        throws Exception
    {
        doSigGenerateTest("DSA-1024-160.sec", "DSA-1024-160.pub", PGPUtil.SHA512);
    }

    public void testGenerateK2048H256()
        throws Exception
    {
        doSigGenerateTest("DSA-2048-224.sec", "DSA-2048-224.pub", PGPUtil.SHA256);
    }

    public void testGenerateK2048H512()
        throws Exception
    {
        doSigGenerateTest("DSA-2048-224.sec", "DSA-2048-224.pub", PGPUtil.SHA512);
    }

    private void doSigGenerateTest(String privateKeyFile, String publicKeyFile, int digest)
        throws Exception
    {
        PGPSecretKeyRing      secRing = loadSecretKey(privateKeyFile);
        PGPPublicKeyRing      pubRing = loadPublicKey(publicKeyFile);
        String                data = "hello world!";
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ByteArrayInputStream  testIn = new ByteArrayInputStream(data.getBytes());
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.DSA, digest).setProvider("BC"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, secRing.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build("test".toCharArray())));

        BCPGOutputStream bcOut = new BCPGOutputStream(bOut);

        sGen.generateOnePassVersion(false).encode(bcOut);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();

        Date testDate = new Date((System.currentTimeMillis() / 1000) * 1000);
        OutputStream lOut = lGen.open(
            new UncloseableOutputStream(bcOut),
            PGPLiteralData.BINARY,
            "_CONSOLE",
            data.getBytes().length,
            testDate);

        int ch;
        while ((ch = testIn.read()) >= 0)
        {
            lOut.write(ch);
            sGen.update((byte)ch);
        }

        lGen.close();

        sGen.generate().encode(bcOut);

        JcaPGPObjectFactory        pgpFact = new JcaPGPObjectFactory(bOut.toByteArray());
        PGPOnePassSignatureList p1 = (PGPOnePassSignatureList)pgpFact.nextObject();
        PGPOnePassSignature     ops = p1.get(0);

        assertEquals(digest, ops.getHashAlgorithm());
        assertEquals(PublicKeyAlgorithmTags.DSA, ops.getKeyAlgorithm());

        PGPLiteralData          p2 = (PGPLiteralData)pgpFact.nextObject();
        if (!p2.getModificationTime().equals(testDate))
        {
            fail("Modification time not preserved");
        }

        InputStream             dIn = p2.getInputStream();

        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubRing.getPublicKey());

        while ((ch = dIn.read()) >= 0)
        {
            ops.update((byte)ch);
        }

        PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();
        PGPSignature sig = p3.get(0);

        assertEquals(digest, sig.getHashAlgorithm());
        assertEquals(PublicKeyAlgorithmTags.DSA, sig.getKeyAlgorithm());

        assertTrue(ops.verify(sig));
    }

    private void doSigVerifyTest(
        String      publicKeyFile,
        String      sigFile)
        throws Exception
    {
        PGPPublicKeyRing publicKey = loadPublicKey(publicKeyFile);
        JcaPGPObjectFactory pgpFact = loadSig(sigFile);

        PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();

        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

        PGPOnePassSignatureList p1 = (PGPOnePassSignatureList)pgpFact.nextObject();
        PGPOnePassSignature ops = p1.get(0);

        PGPLiteralData p2 = (PGPLiteralData)pgpFact.nextObject();

        InputStream dIn = p2.getInputStream();

        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey.getPublicKey());

        int ch;
        while ((ch = dIn.read()) >= 0)
        {
            ops.update((byte)ch);
        }

        PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();

        assertTrue(ops.verify(p3.get(0)));
    }

    private JcaPGPObjectFactory loadSig(
        String sigName)
        throws Exception
    {
        return new JcaPGPObjectFactory(this.getClass().getResourceAsStream("dsa/sigs/" + sigName));
    }

    private PGPPublicKeyRing loadPublicKey(
        String keyName)
        throws Exception
    {
        return new PGPPublicKeyRing(this.getClass().getResourceAsStream("dsa/keys/" + keyName), new JcaKeyFingerprintCalculator());
    }

    private PGPSecretKeyRing loadSecretKey(
        String keyName)
        throws Exception
    {
        return new PGPSecretKeyRing(this.getClass().getResourceAsStream("dsa/keys/" + keyName), new JcaKeyFingerprintCalculator());
    }

    public static void main (String[] args)
        throws Exception
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("GPG DSA2 tests");

        suite.addTestSuite(DSA2Test.class);

        return suite;
    }
}
