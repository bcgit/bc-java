package org.bouncycastle.est.test;


import java.io.InputStreamReader;
import java.security.Security;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.est.jcajce.JsseDefaultHostnameAuthorizer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * TestHostNameAuthorizer tests the hostname authorizer only. EST related functions
 * are not tested here.
 */
public class TestHostNameAuthorizer
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static X509Certificate readPemCertificate(String path)
        throws Exception
    {
        InputStreamReader fr = new InputStreamReader(TestHostNameAuthorizer.class.getResourceAsStream(path));
        PemReader reader = new PemReader(fr);
        X509CertificateHolder fromFile = new X509CertificateHolder(reader.readPemObject().getContent());
        reader.close();
        fr.close();
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(fromFile);
    }

    /*
        The following tests do not attempt to validate the certificates.
        They only test hostname verification behavior.
     */
    public void testCNMatch()
        throws Exception
    {
        X509Certificate cert = readPemCertificate("san/cert_cn_match_wc.pem");

        // the subject CN is only consulted when the fallback property is explicitly "true"
        String saved = System.getProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK);
        System.setProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK, "true");
        try
        {
            assertTrue("Common Name match", new JsseDefaultHostnameAuthorizer(null).verify("aardvark.cisco.com", cert));
            assertFalse("Not match", new JsseDefaultHostnameAuthorizer(null).verify("cisco.com", cert));
        }
        finally
        {
            restoreCNFallback(saved);
        }
    }

    public void testCNFallbackDisabledByDefault()
        throws Exception
    {
        X509Certificate cert = readPemCertificate("san/cert_cn_match_wc.pem");

        String saved = System.getProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK);
        System.clearProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK);
        try
        {
            assertFalse("SAN-less certificate accepted by CN match with the fallback property unset",
                new JsseDefaultHostnameAuthorizer(null).verify("aardvark.cisco.com", cert));
        }
        finally
        {
            restoreCNFallback(saved);
        }
    }

    public void testCNFallbackDisabledWhenPropertyFalse()
        throws Exception
    {
        X509Certificate cert = readPemCertificate("san/cert_cn_match_wc.pem");

        String saved = System.getProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK);
        System.setProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK, "false");
        try
        {
            assertFalse("SAN-less certificate accepted by CN match with the fallback property false",
                new JsseDefaultHostnameAuthorizer(null).verify("aardvark.cisco.com", cert));
        }
        finally
        {
            restoreCNFallback(saved);
        }
    }

    private static void restoreCNFallback(String saved)
    {
        if (saved == null)
        {
            System.clearProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK);
        }
        else
        {
            System.setProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK, saved);
        }
    }

    public void testCNMismatch_1()
        throws Exception
    {
        X509Certificate cert = readPemCertificate("san/cert_cn_mismatch_wc.pem");

        assertFalse("Not match", new JsseDefaultHostnameAuthorizer(null).verify("aardvark", cert));
    }


    // 192.168.1.50
    public void testCNIPMismatch()
        throws Exception
    {
        X509Certificate cert = readPemCertificate("san/cert_cn_mismatch_ip.pem");

        assertFalse("Not match", new JsseDefaultHostnameAuthorizer(null).verify("127.0.0.1", cert));
    }

    public void testWCMismatch()
        throws Exception
    {
        X509Certificate cert = readPemCertificate("san/cert_cn_mismatch_ip.pem");

        assertFalse("Not match", new JsseDefaultHostnameAuthorizer(null).verify("aardvark.cisco.com", cert));
    }

    public void testSANMatch()
        throws Exception
    {
        X509Certificate cert = readPemCertificate("san/cert_san_match.pem");
        assertTrue("Match", new JsseDefaultHostnameAuthorizer(null).verify("localhost.cisco.com", cert));
    }

    public void testSANMatchIP()
        throws Exception
    {
        X509Certificate cert = readPemCertificate("san/cert_san_match_ip.pem");
        assertTrue("Match", new JsseDefaultHostnameAuthorizer(null).verify("192.168.51.140", cert));
        assertTrue("Match", new JsseDefaultHostnameAuthorizer(null).verify("127.0.0.1", cert));
        assertFalse("Not Match", new JsseDefaultHostnameAuthorizer(null).verify("10.0.0.1", cert));
    }

    public void testSANMatchWC()
        throws Exception
    {
        X509Certificate cert = readPemCertificate("san/cert_san_mismatch_wc.pem");
        assertTrue("Match", new JsseDefaultHostnameAuthorizer(null).verify("roundhouse.yahoo.com", cert));
        assertFalse("Not Match", new JsseDefaultHostnameAuthorizer(null).verify("aardvark.cisco.com", cert));
    }

    public void testSANMismatchIP()
        throws Exception
    {
        X509Certificate cert = readPemCertificate("san/cert_san_mismatch_ip.pem");
        assertFalse("Not Match", new JsseDefaultHostnameAuthorizer(null).verify("localhost.me", cert));
    }

    public void testSANMismatchWC()
        throws Exception
    {
        X509Certificate cert = readPemCertificate("san/cert_san_mismatch_wc.pem");
        assertFalse("Not Match", new JsseDefaultHostnameAuthorizer(null).verify("localhost.me", cert));
    }
}
