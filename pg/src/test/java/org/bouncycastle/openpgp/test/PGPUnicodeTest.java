package org.bouncycastle.openpgp.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.Security;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class PGPUnicodeTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    public void test_key(BigInteger keyId, String passphrase)
        throws Exception
    {

        PGPSecretKeyRingCollection secretKeyRing = loadSecretKeyCollection("secring.gpg");

        PGPSecretKeyRing secretKey = secretKeyRing.getSecretKeyRing(keyId.longValue());
        assertNotNull("Could not locate secret keyring with Id=" + keyId.toString(16), secretKey);

        PGPSecretKey key = secretKey.getSecretKey();
        assertNotNull("Could not locate secret key!", key);

        try
        {
            PGPDigestCalculatorProvider calcProvider = new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();

            PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder(calcProvider)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passphrase.toCharArray());

            PGPPrivateKey privateKey = key.extractPrivateKey(decryptor);

            assertTrue(privateKey.getKeyID() == keyId.longValue());

        }
        catch (PGPException e)
        {
            throw new PGPException("Password incorrect!", e);
        }

        // all fine!
    }

    public void test_UmlautPassphrase()
    {

        try
        {
            BigInteger keyId = new BigInteger("362961283C48132B9F14C5C3EC87272EFCB986D2", 16);

            String passphrase = new String("H\u00e4ndle".getBytes("UTF-16"), "UTF-16");
//            FileInputStream passwordFile = new FileInputStream("testdata/passphrase_for_test.txt");
//            byte[] password = new byte[passwordFile.available()];
//            passwordFile.read(password);
//            passwordFile.close();
//            String passphrase = new String(password);            

            test_key(keyId, passphrase);

            // all fine!

        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    public void test_ASCIIPassphrase()
    {

        try
        {
            BigInteger keyId = new BigInteger("A392B7310C64026022405257AA2AAAC7CB417459", 16);

            String passphrase = "Admin123";

            test_key(keyId, passphrase);

            // all fine!

        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    public void test_CyrillicPassphrase()
    {

        try
        {
            BigInteger keyId = new BigInteger("B7773AF32BE4EC1806B1BACC4680E7F3960C44E7", 16);

            // XXX The password text file must not have the UTF-8 BOM !
            // Ref: http://stackoverflow.com/questions/2223882/whats-different-between-utf-8-and-utf-8-without-bom

            InputStream passwordFile = this.getClass().getResourceAsStream("unicode/" + "passphrase_cyr.txt");
            Reader reader = new InputStreamReader(passwordFile, Charset.forName("UTF-8"));
            BufferedReader in = new BufferedReader(reader);
            String passphrase = in.readLine();
            in.close();
            passwordFile.close();

            test_key(keyId, passphrase);

            // all fine!

        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    private PGPSecretKeyRingCollection loadSecretKeyCollection(
        String keyName)
        throws Exception
    {
        return new PGPSecretKeyRingCollection(this.getClass().getResourceAsStream("unicode/" + keyName), new JcaKeyFingerprintCalculator());
    }

    public static void main (String[] args)
        throws Exception
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("Unicode Password tests");

        suite.addTestSuite(PGPUnicodeTest.class);

        return suite;
    }
}
