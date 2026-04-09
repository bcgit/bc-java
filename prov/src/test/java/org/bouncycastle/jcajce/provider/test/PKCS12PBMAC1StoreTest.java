package org.bouncycastle.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.BCLoadStoreParameter;
import org.bouncycastle.jcajce.PKCS12LoadStoreParameter;
import org.bouncycastle.jcajce.PKCS12StoreParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class PKCS12PBMAC1StoreTest
    extends TestCase
{
    //private static final String _BC = BouncyCastleProvider.PROVIDER_NAME;
    private final static char[] passwd = "hello world".toCharArray();
    private static byte[] _currentPKCS12Object = null;

    static final ASN1ObjectIdentifier id_PBMAC1 = PKCSObjectIdentifiers.pkcs_5.branch("14");

    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

    protected void setUp()
    {
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
    }

    ///////////////////////////////////////////////////////////////////////////
    // This simply tests whether we can obtain our revised PKCS12KeyStoreSpi
    ///////////////////////////////////////////////////////////////////////////
    public void testPbmac1()
        throws Exception
    {
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12-PBMAC1", "BC");
    }

    //
    // test the new "no password" format for cacerts
    //
    public void testCaCerts()
        throws Exception
    {
        InputStream inS = this.getClass().getResourceAsStream("sample_cacerts.p12");
        KeyStore ks = KeyStore.getInstance("PKCS12-PBMAC1", "BC");

        ks.load(inS, null);

        Set<String> expected = new HashSet<String>();
        expected.add("debian:entrust_root_certification_authority_-_g2.pem.crt [jdk]");
        expected.add("debian:entrust_root_certification_authority_-_g4.pem.crt [jdk]");
        expected.add("debian:entrust.net_premium_2048_secure_server_ca.pem.crt [jdk]");
        expected.add("debian:identrust_public_sector_root_ca_1.pem.crt [jdk]");
        expected.add("debian:identrust_commercial_root_ca_1.pem.crt [jdk]");
        expected.add("debian:entrust_root_certification_authority_-_ec1.pem.crt [jdk]");
        expected.add("debian:entrust_root_certification_authority.pem.crt [jdk]");

        KeyStore ks2 = KeyStore.getInstance("PKCS12-PBMAC1", "BC");

        ks2.load(null, null);

        for (Enumeration en = ks.aliases(); en.hasMoreElements(); )
        {
            String certName = (String)en.nextElement();
            expected.remove(certName);

            ks2.setCertificateEntry(certName, ks.getCertificate(certName));
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ks2.store(bOut, null);

        assertEquals(0, expected.size());
    }

    public void testDefaultPbmac1()
        throws Exception
    {
        KeyStore sourceP12 = KeyStore.getInstance("PKCS12-PBMAC1", "BC");
        ByteArrayInputStream inStream = new ByteArrayInputStream(PKCS12TestData._non_PBMAC1_PKCS12);
        sourceP12.load(inStream, passwd);

        KeyStore pkcs12 = KeyStore.getInstance("PKCS12-PBMAC1", "BC");

        pkcs12.load(null, null);

        pkcs12.setCertificateEntry("alpha", sourceP12.getCertificate("oreste"));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        pkcs12.store(bOut, "4567".toCharArray());

        Pfx pfx = Pfx.getInstance(bOut.toByteArray());

        assertEquals(id_PBMAC1, pfx.getMacData().getMac().getAlgorithmId().getAlgorithm());
    }

    ///////////////////////////////////////////////////////////////////////////
    // This test will read in a PKCS12 object with the default MAC, we then
    // convert the MAC to PBMAC1 format.
    ///////////////////////////////////////////////////////////////////////////
    public void testConvertDefaultMacToPBMAC1()
        throws Exception
    {
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12-PBMAC1", "BC");
        ByteArrayInputStream inStream = new ByteArrayInputStream(PKCS12TestData._non_PBMAC1_PKCS12);
        pkcs12.load(inStream, passwd);

        PKCS12StoreParameter.PBMAC1WithPBKDF2Builder pbmacBuilder = PKCS12StoreParameter.pbmac1WithPBKDF2Builder();
        byte[] mSalt = new byte[20];
        SecureRandom random = new SecureRandom();
        random.nextBytes(mSalt);
        pbmacBuilder.setSalt(mSalt);
        AlgorithmIdentifier macAlgorithm = pbmacBuilder.build();

        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        PKCS12StoreParameter.Builder builder = PKCS12StoreParameter.builder(outStream, passwd);
        builder.setMacAlgorithm(macAlgorithm);
        PKCS12StoreParameter storeParam = builder.build();
        pkcs12.store(storeParam);
        _currentPKCS12Object = outStream.toByteArray();
    }

    public void testJSafeInternationalIssue()
        throws Exception
    {
        InputStream inS = this.getClass().getResourceAsStream("empty.p12");
        KeyStore ks = KeyStore.getInstance("PKCS12-PBMAC1", "BC");

        BCLoadStoreParameter p12Param = new PKCS12LoadStoreParameter.Builder(inS, new KeyStore.PasswordProtection("Mötley Crüe".toCharArray())).setUseISO8859d1ForDecryption(true).build();

        ks.load(p12Param);

        inS = this.getClass().getResourceAsStream("with-key-entry.p12");
        ks = KeyStore.getInstance("PKCS12-PBMAC1", "BC");

        p12Param = new PKCS12LoadStoreParameter.Builder(inS, new KeyStore.PasswordProtection("Mötley Crüe".toCharArray())).setUseISO8859d1ForDecryption(true).build();
        
        ks.load(p12Param);

        Set<String> expected = new HashSet<String>();

        expected.add("cn=issuer");
        expected.add("alias");

        for (Enumeration en = ks.aliases(); en.hasMoreElements(); )
        {
            String alias = (String)en.nextElement();
            expected.remove(alias);
        }

        assertEquals(0, expected.size());
    }

    public void testPBMac1PBKdf2()
        throws Exception
    {
        KeyStore store = KeyStore.getInstance("PKCS12-PBMAC1", "BC");
        final char[] password = "1234".toCharArray();
        ByteArrayInputStream stream;
        // valid test vectors
        for (byte[] test_vector : new byte[][]{PKCS12TestData.pkcs12WithPBMac1PBKdf2_a1, PKCS12TestData.pkcs12WithPBMac1PBKdf2_a2, PKCS12TestData.pkcs12WithPBMac1PBKdf2_a3})
        {
            //
            // load test
            //
            stream = new ByteArrayInputStream(test_vector);
            store.load(stream, password);

            try
            {
                store.load(stream, "not right".toCharArray());
                fail("no exception");
            }
            catch (IOException ignored)
            {
            }

            //
            // save test
            //
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            store.store(bOut, passwd);
            stream = new ByteArrayInputStream(bOut.toByteArray());
            store.load(stream, passwd);

            //
            // save test using LoadStoreParameter
            //
            bOut = new ByteArrayOutputStream();
            org.bouncycastle.jcajce.PKCS12StoreParameter storeParam = new org.bouncycastle.jcajce.PKCS12StoreParameter(bOut, passwd, true);
            store.store(storeParam);
            byte[] data = bOut.toByteArray();
            stream = new ByteArrayInputStream(data);
            store.load(stream, passwd);
        }
        // invalid test vectors
        for (byte[] test_vector : new byte[][]{PKCS12TestData.pkcs12WithPBMac1PBKdf2_a4, PKCS12TestData.pkcs12WithPBMac1PBKdf2_a5})
        {
            stream = new ByteArrayInputStream(test_vector);
            try
            {
                store.load(stream, password);
                fail("no exception");
            }
            catch (IOException e)
            {
                assertTrue(e.getMessage().contains("PKCS12 key store mac invalid - wrong password or corrupted file"));
            }
        }
        // invalid test vector that throws exception
        stream = new ByteArrayInputStream(PKCS12TestData.pkcs12WithPBMac1PBKdf2_a6);
        try
        {
            store.load(stream, password);
            fail("no exception");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage().contains("Key length must be present when using PBMAC1."));
        }
    }

    public void testDodgyInputs()
        throws Exception
    {
        byte[] negIt = Hex.decode("3049020103301106092a864879f70d010706a004040230003031302130" +
            "0906052b0e03021a0500041400000100000000000000000000000000" +
            "00000000040800000000000000000202f300");
        
        KeyStore ks = KeyStore.getInstance("PKCS12-PBMAC1", "BC");

        try
        {
            ks.load(new ByteArrayInputStream(negIt), passwd);
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            assertEquals("negative iteration count found", e.getMessage());
        }

    }
}
