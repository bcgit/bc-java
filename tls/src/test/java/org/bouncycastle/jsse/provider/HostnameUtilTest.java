package org.bouncycastle.jsse.provider;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import junit.framework.TestCase;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Properties;

/**
 * Regression test for the JSSE hostname verifier's legacy "match the subject CN when no dNSName SAN
 * is present" fallback. The fallback is a Name-Constraints bypass surface (a dNSName-constrained
 * sub-CA can issue a SAN-less leaf whose CN names an unrelated host, since name constraints only
 * constrain SAN entries of the constrained type) and is gated behind
 * {@link Properties#JSSE_HOSTNAME_CHECK_CN_FALLBACK}. The gate must default OFF: a SAN-less
 * certificate is accepted by CN match only when the property is explicitly set to "true"
 * (CVD ANT-2026-TVZJ3Z43).
 */
public class HostnameUtilTest
    extends TestCase
{
    private static final String HOST = "test.example.com";

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testCnFallbackDisabledByDefault()
        throws Exception
    {
        String saved = System.getProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK);
        System.clearProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK);
        try
        {
            HostnameUtil.checkHostname(HOST, sanlessCnCert(), true);
            fail("SAN-less certificate accepted by CN match with the fallback property unset");
        }
        catch (CertificateException e)
        {
            // expected: with the property unset the CN fallback is off, so a cert with no matching
            // SAN identifier is rejected.
        }
        finally
        {
            restore(saved);
        }
    }

    public void testCnFallbackDisabledWhenPropertyFalse()
        throws Exception
    {
        String saved = System.getProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK);
        System.setProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK, "false");
        try
        {
            HostnameUtil.checkHostname(HOST, sanlessCnCert(), true);
            fail("SAN-less certificate accepted by CN match with the fallback property false");
        }
        catch (CertificateException e)
        {
            // expected
        }
        finally
        {
            restore(saved);
        }
    }

    public void testCnFallbackEnabledWhenPropertyTrue()
        throws Exception
    {
        String saved = System.getProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK);
        System.setProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK, "true");
        try
        {
            // explicit opt-in restores the legacy SunJSSE-compatible CN match
            HostnameUtil.checkHostname(HOST, sanlessCnCert(), true);
        }
        finally
        {
            restore(saved);
        }
    }

    public void testMatchingDnsSanAlwaysAccepted()
        throws Exception
    {
        // a matching SAN dNSName must satisfy verification regardless of the fallback property
        String saved = System.getProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK);
        System.clearProperty(Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK);
        try
        {
            HostnameUtil.checkHostname(HOST, dnsSanCert(), true);
        }
        finally
        {
            restore(saved);
        }
    }

    private static X509Certificate sanlessCnCert()
        throws Exception
    {
        return buildCert(new X500Name("CN=" + HOST), null);
    }

    private static X509Certificate dnsSanCert()
        throws Exception
    {
        // a deliberately non-matching CN, so a pass can only come from the SAN dNSName
        return buildCert(new X500Name("CN=not-the-host.example.org"), HOST);
    }

    private static X509Certificate buildCert(X500Name dn, String sanDnsName)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            dn, BigInteger.valueOf(now), new Date(now - 5000), new Date(now + 30 * 60 * 1000), dn,
            SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));

        if (sanDnsName != null)
        {
            builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, sanDnsName)));
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(kp.getPrivate());

        return new JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(builder.build(signer));
    }

    private static void restore(String saved)
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
}
