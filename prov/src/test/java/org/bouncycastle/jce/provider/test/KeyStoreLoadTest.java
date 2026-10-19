package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.test.SimpleTest;

/**
 * KeyStore.load() semantics for the BC key stores: a null stream makes the store empty, a stream replaces
 * what the store held, and a load that fails leaves the store as it was, as the JDK's own key stores do.
 */
public class KeyStoreLoadTest
    extends SimpleTest
{
    private static final char[] PASSWORD = "hello world".toCharArray();

    private static final String[] TYPES = { "PKCS12", "PKCS12-PBMAC1", "BKS", "UBER", "BCFKS", "BCFKS-DEF", "FIPS" };

    private X509Certificate cert1;
    private X509Certificate cert2;

    public String getName()
    {
        return "KeyStoreLoad";
    }

    private static Vector aliases(KeyStore ks)
        throws Exception
    {
        Vector v = new Vector();
        for (Enumeration en = ks.aliases(); en.hasMoreElements();)
        {
            v.addElement(en.nextElement());
        }
        return v;
    }

    private byte[] storeWith(String type, String[] names, X509Certificate cert)
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance(type, "BC");
        ks.load(null, null);
        for (int i = 0; i != names.length; i++)
        {
            ks.setCertificateEntry(names[i], cert);
        }
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ks.store(bOut, PASSWORD);
        return bOut.toByteArray();
    }

    private void checkType(String type)
        throws Exception
    {
        byte[] first = storeWith(type, new String[]{ "a", "b" }, cert1);
        byte[] second = storeWith(type, new String[]{ "c" }, cert2);

        KeyStore ks = KeyStore.getInstance(type, "BC");

        ks.load(new ByteArrayInputStream(first), PASSWORD);
        isEquals(type + " loaded", 2, ks.size());
        ks.load(null, null);
        isEquals(type + " load(null) leaves entries", 0, ks.size());

        ks.load(new ByteArrayInputStream(first), PASSWORD);
        ks.load(new ByteArrayInputStream(second), PASSWORD);
        isTrue(type + " second load did not replace the first", aliases(ks).size() == 1 && ks.containsAlias("c"));

        // a file damaged after its header, so the failure comes late in the load
        byte[] corrupt = (byte[])first.clone();
        for (int i = corrupt.length - 8; i != corrupt.length; i++)
        {
            corrupt[i] ^= 0x55;
        }
        ks.load(new ByteArrayInputStream(first), PASSWORD);
        try
        {
            ks.load(new ByteArrayInputStream(corrupt), PASSWORD);
            fail(type + " corrupt store loaded");
        }
        catch (Exception e)
        {
            isTrue(type + " failed load changed the store", aliases(ks).size() == 2 && ks.containsAlias("a") && ks.containsAlias("b"));
        }

        try
        {
            ks.load(new ByteArrayInputStream(second), "wrong".toCharArray());
            fail(type + " wrong password accepted");
        }
        catch (Exception e)
        {
            isTrue(type + " wrong password changed the store", aliases(ks).size() == 2 && ks.containsAlias("a"));
        }
    }

    private int macIterationCount(byte[] pfxBytes)
        throws Exception
    {
        return Pfx.getInstance(ASN1Primitive.fromByteArray(pfxBytes)).getMacData().getIterationCount().intValue();
    }

    // load(null) puts the MAC defaults back, so a store emptied and refilled does not keep an earlier file's MAC
    private void checkPKCS12MacReset(String type)
        throws Exception
    {
        String prior = System.getProperty(Properties.PKCS12_STORE_IT_COUNT);
        try
        {
            System.setProperty(Properties.PKCS12_STORE_IT_COUNT, "1500");
            byte[] file = storeWith(type, new String[]{ "a" }, cert1);
            isEquals(type + " file MAC count", 3000, macIterationCount(file));

            System.setProperty(Properties.PKCS12_STORE_IT_COUNT, "1024");
            KeyStore ks = KeyStore.getInstance(type, "BC");
            ks.load(new ByteArrayInputStream(file), PASSWORD);
            ks.load(null, null);
            ks.setCertificateEntry("b", cert2);
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ks.store(bOut, PASSWORD);
            isEquals(type + " MAC count kept across load(null)", 2048, macIterationCount(bOut.toByteArray()));
        }
        finally
        {
            if (prior == null)
            {
                System.getProperties().remove(Properties.PKCS12_STORE_IT_COUNT);
            }
            else
            {
                System.setProperty(Properties.PKCS12_STORE_IT_COUNT, prior);
            }
        }
    }

    private byte[] jksWith(KeyStore jdkJks, String[] names, X509Certificate cert)
        throws Exception
    {
        jdkJks.load(null, null);
        for (int i = 0; i != names.length; i++)
        {
            jdkJks.setCertificateEntry(names[i], cert);
        }
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        jdkJks.store(bOut, PASSWORD);
        return bOut.toByteArray();
    }

    // the FIPS store reads JKS files through the JKS reader, which used to add each load's entries to the last
    private void checkJKS()
        throws Exception
    {
        KeyStore jdkJks;
        try
        {
            jdkJks = KeyStore.getInstance("JKS", "SUN");
        }
        catch (Exception e)
        {
            return;     // no JDK JKS implementation to write the files with
        }

        byte[] first = jksWith(jdkJks, new String[]{ "a", "b" }, cert1);
        byte[] second = jksWith(jdkJks, new String[]{ "c" }, cert2);
        byte[] corrupt = (byte[])second.clone();
        corrupt[corrupt.length - 1] ^= 1;

        KeyStore ks = KeyStore.getInstance("FIPS", "BC");
        ks.load(new ByteArrayInputStream(first), PASSWORD);
        isEquals("JKS loaded", 2, ks.size());
        ks.load(new ByteArrayInputStream(second), PASSWORD);
        isTrue("JKS second load did not replace the first", aliases(ks).size() == 1 && ks.containsAlias("c"));
        try
        {
            ks.load(new ByteArrayInputStream(corrupt), PASSWORD);
            fail("corrupt JKS loaded");
        }
        catch (Exception e)
        {
            isTrue("failed JKS load changed the store", aliases(ks).size() == 1 && ks.containsAlias("c"));
        }
        ks.load(null, null);
        isEquals("JKS load(null) leaves entries", 0, ks.size());
    }

    public void performTest()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        cert1 = TestUtils.createSelfSignedCert("CN=Load Test 1", "SHA256withECDSA", kp);
        cert2 = TestUtils.createSelfSignedCert("CN=Load Test 2", "SHA256withECDSA", kp);

        for (int i = 0; i != TYPES.length; i++)
        {
            checkType(TYPES[i]);
        }
        checkPKCS12MacReset("PKCS12");
        checkPKCS12MacReset("PKCS12-PBMAC1");
        checkJKS();
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new KeyStoreLoadTest());
    }
}
