package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Exercise the various key stores, making sure we at least get back what we put in!
 * <p>
 * This tests both the BKS, and the UBER key store.
 */
public class KeyStoreTest
    extends SimpleTest
{
    static char[]   passwd = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };

    byte[] v1BKS = Base64.decode(
          "AAAAAQAAABTqZbNMyPjsFazhFplWWDMBLPRdRAAABcYEAAdhbmRyb2lkAAAB"
        + "NOifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8"
        + "q20AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wD0b8OP5/XzOz/8knhxmqJZ"
        + "3yRJMw==");
    byte[] v2BKS = Base64.decode(
          "AAAAAgAAABSkmTXz4VIznO1SSUqsIHdxWcxsuQAABFMEAAdhbmRyb2lkAAABN" +
          "OifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8q2" +
          "0AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wBO59KOGPvSrmJpd32P6ZAh9qLZJw==");

    byte[] v1UBER = Base64.decode(
          "AAAAAQAAABRP0F6p2p3FyQKqyJiJt3NbvdybiwAAB2znqrO779YIW5gMtbt+"
        + "NUs96VPPcfZiKJPg7RKH7Yu3CQB0/g9nYsvgFB0fQ05mHcW3KjntN2/31A6G"
        + "i00n4ZnUTjJL16puZnQrloeGXxFy58tjwkFuwJ7V7ELYgiZlls0beHSdDGQW"
        + "iyYECwWs1la/");
    byte[] v2UBER = Base64.decode(
          "AAAAAgAAABQ/D9k3376OG/REg4Ams9Up332tLQAABujoVcsRcKWwhlo4mMg5"
        + "lF2vJfK+okIYecJGWCvdykF5r8kDn68llt52IDXDkpRXVXcNJ0/aD7sa7iZ0"
        + "SL0TAwcfp/9v4j/w8slj/qgO0i/76+zROrP0NGFIa5k/iOg5Z0Tj77muMaJf"
        + "n3vLlIHa4IsX");

    byte[] negSaltBKS = Base64.decode(
          "AAAAAv////+WnyglO06djy6JgCxGiIemnZdcOwAAB2AEAAdhbmRyb2lkAAAB" +
          "NOifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8" +
          "q20AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wDrg6gUHsh27wNjUwkR+REe" +
          "NeFYBg==");

    char[] oldStorePass = "fredfred".toCharArray();

    public void ecStoreTest(
        String  storeName)
        throws Exception
    {
        X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec ecSpec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

        KeyPairGenerator    g = KeyPairGenerator.getInstance("ECDSA", "BC");

        g.initialize(ecSpec, new SecureRandom());

        KeyPair     keyPair = g.generateKeyPair();

        PublicKey   pubKey = keyPair.getPublic();
        PrivateKey  privKey = keyPair.getPrivate();

        //
        // distinguished name table.
        //
        X500NameBuilder nBldr = new X500NameBuilder();

        nBldr.addRDN(BCStyle.C, "AU");
        nBldr.addRDN(BCStyle.O,"The Legion of the Bouncy Castle");
        nBldr.addRDN(BCStyle.L, "Melbourne");
        nBldr.addRDN(BCStyle.ST,"Victoria");
        nBldr.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");
        
        Certificate[]    chain = new Certificate[1];

        try
        {
            X509Certificate cert = TestCertificateGen.createSelfSignedCert(nBldr.build(), "SHA1withECDSA", new KeyPair(pubKey, privKey));

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory      fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);

            chain[0] = cert;
        }
        catch (Exception e)
        {
            fail("error generating cert - " + e.toString());
        }

        KeyStore store = KeyStore.getInstance(storeName, "BC");

        store.load(null, null);

        store.setKeyEntry("private", privKey, passwd, chain);

        //
        // write out and read back store
        //
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

        store.store(bOut, passwd);

        ByteArrayInputStream    bIn = new ByteArrayInputStream(bOut.toByteArray());

        //
        // start with a new key store
        //
        store = KeyStore.getInstance(storeName, "BC");

        store.load(bIn, passwd);

        //
        // load the private key
        //
        privKey = (PrivateKey)store.getKey("private", passwd);

        //
        // double public key encoding test
        //
        byte[]              pubEnc = pubKey.getEncoded();
        KeyFactory          keyFac = KeyFactory.getInstance(pubKey.getAlgorithm(), "BC");
        X509EncodedKeySpec  pubX509 = new X509EncodedKeySpec(pubEnc);

        pubKey = (PublicKey)keyFac.generatePublic(pubX509);

        pubEnc = pubKey.getEncoded();
        keyFac = KeyFactory.getInstance(pubKey.getAlgorithm(), "BC");
        pubX509 = new X509EncodedKeySpec(pubEnc);

        pubKey = (PublicKey)keyFac.generatePublic(pubX509);

        //
        // double private key encoding test
        //
        byte[]              privEnc = privKey.getEncoded();

        keyFac = KeyFactory.getInstance(privKey.getAlgorithm(), "BC");

        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        privKey = (PrivateKey)keyFac.generatePrivate(privPKCS8);

        keyFac = KeyFactory.getInstance(privKey.getAlgorithm(), "BC");
        privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        privKey = (PrivateKey)keyFac.generatePrivate(privPKCS8);
    }

    public void keyStoreTest(
        String    storeName)
        throws Exception
    {
        KeyStore store = KeyStore.getInstance(storeName, "BC");

        store.load(null, null);

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");

        gen.initialize(1024, new SecureRandom());

        KeyPair         pair = gen.generateKeyPair();
        RSAPrivateKey   privKey = (RSAPrivateKey)pair.getPrivate();
        RSAPublicKey    pubKey = (RSAPublicKey)pair.getPublic();
        BigInteger      modulus = privKey.getModulus();
        BigInteger      privateExponent = privKey.getPrivateExponent();


        //
        // distinguished name table.
        //
        X500NameBuilder nBldr = new X500NameBuilder();

        nBldr.addRDN(BCStyle.C, "AU");
        nBldr.addRDN(BCStyle.O,"The Legion of the Bouncy Castle");
        nBldr.addRDN(BCStyle.L, "Melbourne");
        nBldr.addRDN(BCStyle.ST,"Victoria");
        nBldr.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");

        //
        // extensions
        //

        //
        // create the certificate.
        //
        Certificate[]   chain = new Certificate[1];

        try
        {
            X509Certificate cert = TestCertificateGen.createSelfSignedCert(nBldr.build(), "MD5WithRSAEncryption", new KeyPair(pubKey, privKey));

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory      fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);

            chain[0] = cert;
        }
        catch (Exception e)
        {
            fail("error generating cert - " + e.toString());
        }

        store.setKeyEntry("private", privKey, passwd, chain);

        //
        // write out and read back store
        //
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

        store.store(bOut, passwd);

        ByteArrayInputStream    bIn = new ByteArrayInputStream(bOut.toByteArray());

        //
        // start with a new key store
        //
        store = KeyStore.getInstance(storeName, "BC");

        store.load(bIn, passwd);

        //
        // verify public key
        //
        privKey = (RSAPrivateKey)store.getKey("private", passwd);

        if (!privKey.getModulus().equals(modulus))
        {
            fail("private key modulus wrong");
        }
        else if (!privKey.getPrivateExponent().equals(privateExponent))
        {
            fail("private key exponent wrong");
        }

        //
        // verify certificate
        //
        Certificate cert = store.getCertificateChain("private")[0];

        cert.verify(pubKey);
    }

    // CVE-2018-5382: the default BKS keystore must refuse to load a legacy version 0/1 store
    // (which derives a 16-bit, brute-forceable HMAC integrity key) unless the caller has explicitly
    // opted in via org.bouncycastle.bks.enable_v1. The test harness sets that system property, so
    // we override it off on this thread to exercise the default behaviour.
    private void v1RejectedByDefaultTest()
        throws Exception
    {
        Properties.setThreadOverride(Properties.BKS_ENABLE_V1, false);
        try
        {
            KeyStore ks = KeyStore.getInstance("BKS", "BC");

            ks.load(new ByteArrayInputStream(v1BKS), oldStorePass);

            fail("default BKS loaded a version 1 store without " + Properties.BKS_ENABLE_V1);
        }
        catch (IOException e)
        {
            if (!e.getMessage().startsWith("BKS version 1 keystore not supported"))
            {
                fail("unexpected exception: " + e.getMessage());
            }
        }
        finally
        {
            Properties.removeThreadOverride(Properties.BKS_ENABLE_V1);
        }
    }

    private void oldStoreTest()
        throws Exception
    {
        checkStore(KeyStore.getInstance("BKS", "BC"), v1BKS);
        checkStore(KeyStore.getInstance("BKS", "BC"), v2BKS);
        checkStore(KeyStore.getInstance("UBER", "BC"), v1UBER);
        checkStore(KeyStore.getInstance("UBER", "BC"), v2UBER);

        checkOldStore(KeyStore.getInstance("BKS-V1", "BC"), v1BKS);
        checkOldStore(KeyStore.getInstance("BKS-V1", "BC"), v2BKS);
    }

    private void checkStore(KeyStore ks, byte[] data)
        throws Exception
    {
        ks.load(new ByteArrayInputStream(data), oldStorePass);

        if (!ks.containsAlias("android"))
        {
            fail("cannot find alias");
        }

        Key key = ks.getKey("android", oldStorePass);
        if (key == null)
        {
            fail("cannot find key");
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        ks.store(bOut, oldStorePass);
    }

    private void checkOldStore(KeyStore ks, byte[] data)
        throws Exception
    {
        ks.load(new ByteArrayInputStream(data), oldStorePass);

        if (!ks.containsAlias("android"))
        {
            fail("cannot find alias");
        }

        Key key = ks.getKey("android", oldStorePass);
        if (key == null)
        {
            fail("cannot find key");
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        ks.store(bOut, oldStorePass);

        if (data.length != bOut.toByteArray().length)
        {
            fail("Old version key store write incorrect");
        }
    }

    private void checkException()
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance("BKS", "BC");

        try
        {
            ks.load(new ByteArrayInputStream(negSaltBKS), oldStorePass);
        }
        catch (IOException e)
        {
            if (!e.getMessage().equals("Invalid salt detected"))
            {
                fail("negative salt length not detected");
            }
        }

        X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec ecSpec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

        KeyPairGenerator    g = KeyPairGenerator.getInstance("ECDSA", "BC");

        g.initialize(ecSpec, new SecureRandom());

        KeyPair     keyPair = g.generateKeyPair();

        PublicKey   pubKey = keyPair.getPublic();
        PrivateKey  privKey = keyPair.getPrivate();

        //
        // distinguished name table.
        //
        X500NameBuilder nBldr = new X500NameBuilder();

        nBldr.addRDN(BCStyle.C, "AU");
        nBldr.addRDN(BCStyle.O,"The Legion of the Bouncy Castle");
        nBldr.addRDN(BCStyle.L, "Melbourne");
        nBldr.addRDN(BCStyle.ST,"Victoria");
        nBldr.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");

        //
        // create the certificate - version 3
        //
        Certificate[]    dummyChain = new Certificate[1];

        dummyChain[0] = TestCertificateGen.createSelfSignedCert(nBldr.build(), "SHA1withECDSA", new KeyPair(pubKey, privKey));

        ks = KeyStore.getInstance("BKS", "BC");

        ks.load(null, null);

        // add a "protected key" should work
        ks.setKeyEntry("noenc", new PrivateKey()
        {
            public String getAlgorithm()
            {
                return null;
            }

            public String getFormat()
            {
                return null;
            }

            public byte[] getEncoded()
            {
                return null;
            }
        }, new char[0], dummyChain);

        try
        {
            ks.store(new ByteArrayOutputStream(), "hello".toCharArray());
        }
        catch (IOException e)
        {
            isTrue("unable to store encoding of protected key".equals(e.getMessage()));
        }
    }

    public String getName()
    {
        return "KeyStore";
    }

    public void performTest()
        throws Exception
    {
        keyStoreTest("BKS");
        keyStoreTest("UBER");

        keyStoreTest("BKS-V1");

        ecStoreTest("BKS");
        oldStoreTest();
        v1RejectedByDefaultTest();
        checkException();
        checkOversizedEntryRejected();
        checkLargeEntryStreamed();
        checkOversizedIterationCountRejected();
    }

    /*
     * An entry whose declared length genuinely exceeds the read buffer (and whose bytes are
     * actually present) must still load: the incremental read has to consume exactly the
     * declared number of bytes, otherwise the trailing store MAC would misalign and the load
     * would fail. Confirms the bounded-buffer hardening did not turn into a hard size cap.
     */
    private void checkLargeEntryStreamed()
        throws Exception
    {
        int bigLength = (2 * 1024 * 1024) + 1000;   // just over the 2 MiB read buffer

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(2);                            // store version
        dos.writeInt(20);                           // salt length
        dos.write(new byte[20]);                    // salt
        dos.writeInt(1024);                         // iteration count
        dos.write(3);                               // entry type = SECRET
        dos.writeUTF("big");                        // alias
        dos.writeLong(System.currentTimeMillis());  // creation date
        dos.writeInt(0);                            // chain length
        dos.writeInt(bigLength);                    // blob length, > read buffer
        dos.write(new byte[bigLength]);             // the blob bytes really are present
        dos.write(0);                               // NULL entry terminator
        dos.write(new byte[20]);                    // store MAC (not checked for null password)

        KeyStore ks = KeyStore.getInstance("BKS", "BC");
        ks.load(new ByteArrayInputStream(baos.toByteArray()), null);

        isTrue("large entry not loaded", ks.containsAlias("big"));
        isTrue("unexpected entry count", ks.size() == 1);
    }

    /*
     * A crafted BKS/UBER stream declaring an enormous length-prefixed allocation must be
     * rejected with an IOException rather than driving an unbounded array allocation /
     * OutOfMemoryError before the integrity MAC is checked. The poison is reached regardless of
     * the password supplied, since loadStore() runs ahead of the MAC comparison.
     */
    private void checkOversizedEntryRejected()
        throws Exception
    {
        char[][] passwords = {null, new char[0], "test".toCharArray()};

        // BKS: a KEY entry with an Integer.MAX_VALUE certificate chain length.
        ByteArrayOutputStream chainPoison = new ByteArrayOutputStream();
        DataOutputStream c = new DataOutputStream(chainPoison);
        c.writeInt(2);                              // store version
        c.writeInt(20);                             // salt length
        c.write(new byte[20]);                      // salt
        c.writeInt(1024);                           // iteration count
        c.write(2);                                 // entry type = KEY
        c.writeUTF("evil");                         // alias
        c.writeLong(System.currentTimeMillis());    // creation date
        c.writeInt(Integer.MAX_VALUE);              // poison chain length

        // BKS: a SECRET entry (chain length 0) with an Integer.MAX_VALUE blob length.
        ByteArrayOutputStream blobPoison = new ByteArrayOutputStream();
        DataOutputStream b = new DataOutputStream(blobPoison);
        b.writeInt(2);
        b.writeInt(20);
        b.write(new byte[20]);
        b.writeInt(1024);
        b.write(3);                                 // entry type = SECRET
        b.writeUTF("evil");
        b.writeLong(System.currentTimeMillis());
        b.writeInt(0);                              // chain length
        b.writeInt(Integer.MAX_VALUE);              // poison blob length

        // BKS / UBER: an Integer.MAX_VALUE store salt length, read before any cipher is set up.
        ByteArrayOutputStream saltPoison = new ByteArrayOutputStream();
        DataOutputStream s = new DataOutputStream(saltPoison);
        s.writeInt(2);
        s.writeInt(Integer.MAX_VALUE);              // poison salt length

        for (int p = 0; p != passwords.length; p++)
        {
            loadShouldRejectNotOOM("BKS", chainPoison.toByteArray(), passwords[p]);
            loadShouldRejectNotOOM("BKS", blobPoison.toByteArray(), passwords[p]);
            loadShouldRejectNotOOM("BKS", saltPoison.toByteArray(), passwords[p]);
            loadShouldRejectNotOOM("UBER", saltPoison.toByteArray(), passwords[p]);
        }
    }

    private void loadShouldRejectNotOOM(String type, byte[] poison, char[] password)
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance(type, "BC");
        try
        {
            ks.load(new ByteArrayInputStream(poison), password);
            fail("oversized " + type + " allocation not rejected");
        }
        catch (IOException e)
        {
            // expected - the length is rejected before the array is allocated and read
        }
        catch (OutOfMemoryError e)
        {
            fail("oversized " + type + " allocation caused OutOfMemoryError");
        }
    }

    /*
     * A crafted BKS stream declaring an enormous PBE iteration count must be rejected with an
     * IOException up front, rather than running the integrity-MAC key derivation for that many
     * rounds before the MAC is even checked (a pre-integrity CPU-exhaustion DoS). The count is
     * consumed in the password/integrity branch of engineLoad ahead of the MAC comparison, so the
     * cap has to fire there; this mirrors checkOversizedEntryRejected for the CPU- (rather than
     * memory-) exhaustion vector. The cap is lowered via Properties.BKS_MAX_IT_COUNT so the test is
     * deterministic and does not itself run a costly derivation.
     */
    private void checkOversizedIterationCountRejected()
        throws Exception
    {
        String saved = System.getProperty(Properties.BKS_MAX_IT_COUNT);
        System.setProperty(Properties.BKS_MAX_IT_COUNT, "100");
        try
        {
            ByteArrayOutputStream itPoison = new ByteArrayOutputStream();
            DataOutputStream d = new DataOutputStream(itPoison);
            d.writeInt(2);                              // store version
            d.writeInt(20);                             // salt length
            d.write(new byte[20]);                      // salt
            d.writeInt(100000);                         // poison iteration count, far above the cap

            KeyStore ks = KeyStore.getInstance("BKS", "BC");
            try
            {
                // a non-empty password selects the integrity branch, which derives the MAC key
                // from the wire iteration count before the MAC is checked - the vulnerable path.
                ks.load(new ByteArrayInputStream(itPoison.toByteArray()), "test".toCharArray());
                fail("oversized BKS iteration count not rejected");
            }
            catch (IOException e)
            {
                // expected: the cap rejects the count before the PBKDF runs. The message names the
                // iteration count, distinguishing this from the EOFException an uncapped load would
                // only reach after the full derivation.
                isTrue("iteration count not rejected up front: " + e.getMessage(),
                    e.getMessage() != null && e.getMessage().indexOf("iteration count") >= 0);
            }
        }
        finally
        {
            if (saved == null)
            {
                System.getProperties().remove(Properties.BKS_MAX_IT_COUNT);
            }
            else
            {
                System.setProperty(Properties.BKS_MAX_IT_COUNT, saved);
            }
        }
    }

    public static void main(
        String[]    args)
    {
        System.setProperty("org.bouncycastle.bks.enable_v1", "true");

        Security.addProvider(new BouncyCastleProvider());

        runTest(new KeyStoreTest());
    }
}
