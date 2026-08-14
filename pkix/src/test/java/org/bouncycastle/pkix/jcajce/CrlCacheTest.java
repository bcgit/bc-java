package org.bouncycastle.pkix.jcajce;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.PKIXCRLStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Properties;

/**
 * The CRL fetcher must not restrict itself to HTTP. A downcast to HttpURLConnection here caused
 * FTP based CRLs to fail to load - github #1867 removed it from the copy behind the provider's
 * PKIX validator, but this copy kept it, so a distribution point naming any non-HTTP scheme threw
 * an unchecked ClassCastException out of a method that declares IOException / CRLException. Its
 * only caller, X509RevocationChecker.downloadCRLs, catches Exception around the fetch, so the
 * effect was not a propagating crash but a distribution point silently logged as "ignored".
 * <p/>
 * A file: URI stands in for the ftp: one an FTP server would be needed to exercise: both reach the
 * fetcher the same way (only "ldap" is dispatched elsewhere) and both fail on the cast.
 */
public class CrlCacheTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testNonHttpDistributionPoint()
        throws Exception
    {
        URI dp = writeCrlFile();

        assertFalse("file: URI unexpectedly dispatched as ldap", "ldap".equals(dp.getScheme()));

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        // threw ClassCastException on the HttpURLConnection downcast before the fix
        PKIXCRLStore store = CrlCache.getCrl(certFact, new Date(), dp);

        assertNotNull("no CRL store returned for a non-HTTP distribution point", store);
        assertEquals(1, store.getMatches(null).size());
    }

    /**
     * The optional org.bouncycastle.x509.CRLDP_protocols whitelist refuses any protocol it does
     * not name, ahead of the fetch and ahead of the cache.
     */
    public void testProtocolWhitelist()
        throws Exception
    {
        URI dp = writeCrlFile();
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);
        Date now = new Date();

        // unset: unrestricted, and this fetch leaves an entry in the cache
        assertNotNull(CrlCache.getCrl(certFact, now, dp));

        System.setProperty(Properties.X509_CRLDP_PROTOCOLS, "http, https");
        try
        {
            CrlCache.getCrl(certFact, now, dp);
            fail("file: distribution point accepted under an http/https whitelist");
        }
        catch (CRLException e)
        {
            assertEquals("CRL distribution point protocol not permitted: file", e.getMessage());
        }
        finally
        {
            System.getProperties().remove(Properties.X509_CRLDP_PROTOCOLS);
        }

        // naming the protocol permits it again, matched without regard to case
        System.setProperty(Properties.X509_CRLDP_PROTOCOLS, "HTTP,FILE");
        try
        {
            assertNotNull(CrlCache.getCrl(certFact, now, dp));
        }
        finally
        {
            System.getProperties().remove(Properties.X509_CRLDP_PROTOCOLS);
        }
    }

    private URI writeCrlFile()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);
        kpg.initialize(2048);
        KeyPair caKp = kpg.generateKeyPair();

        Date now = new Date();
        Date notBefore = new Date(now.getTime() - 86400000L);
        Date notAfter = new Date(now.getTime() + 86400000L);

        X500Name caName = new X500Name("CN=BC pkix CrlCacheTest CA");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(caKp.getPrivate());

        JcaX509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
            caName, BigInteger.valueOf(1), notBefore, notAfter, caName, caKp.getPublic());
        X509Certificate ca = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certBldr.build(signer));

        JcaX509v2CRLBuilder crlBldr = new JcaX509v2CRLBuilder(ca.getSubjectX500Principal(), now);
        crlBldr.setNextUpdate(notAfter);
        X509CRLHolder crlHolder = crlBldr.build(signer);
        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

        File tmp = File.createTempFile("bc-pkix-crlcache-", ".crl");
        tmp.deleteOnExit();
        FileOutputStream out = new FileOutputStream(tmp);
        out.write(crl.getEncoded());
        out.close();

        return tmp.toURI();
    }
}
