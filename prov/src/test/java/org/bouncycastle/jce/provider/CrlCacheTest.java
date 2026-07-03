package org.bouncycastle.jce.provider;

import java.io.File;
import java.io.FileOutputStream;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.PKIXCRLStore;
import org.bouncycastle.jce.provider.test.TestCertificateGen;
import org.bouncycastle.util.Properties;

/**
 * Lives in the {@code org.bouncycastle.jce.provider} package so it can call the
 * package-private {@link CrlCache#getCrl} entrypoint directly. Exercises the
 * {@link Properties#X509_CRL_CACHE_TTL} eviction behaviour that issue #1833 asked for.
 */
public class CrlCacheTest
    extends TestCase
{
    public String getName()
    {
        return "CrlCache";
    }

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testCache()
        throws Exception
    {
        // Build a small self-signed CA + CRL and write the CRL to a temp file we
        // can point a file: URI at; the prov-side CrlCache fetcher dispatches
        // any non-ldap scheme through URLConnection, which handles file://.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair caKp = kpg.generateKeyPair();
        X509Certificate ca = TestCertificateGen.createSelfSignedCert("CN=BC CrlCacheTest CA", "SHA256withRSA", caKp);
        X509CRL crl = TestCertificateGen.createCRL(ca, caKp.getPrivate(), java.math.BigInteger.valueOf(1));

        File tmp = File.createTempFile("bc-crlcache-", ".crl");
        tmp.deleteOnExit();
        FileOutputStream out = new FileOutputStream(tmp);
        out.write(crl.getEncoded());
        out.close();

        URI dp = tmp.toURI();
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");
        Date now = new Date();

        try
        {
            // 1) cold fetch populates the cache
            PKIXCRLStore a = CrlCache.getCrl(certFact, now, dp);
            assertTrue("first fetch returned null", a != null);

            // 2) immediate re-fetch with no TTL set — same instance (cache hit)
            PKIXCRLStore b = CrlCache.getCrl(certFact, now, dp);
            assertTrue("expected cache hit (same instance)", a == b);

            // 3) TTL = 1 second; sleep past it; expect a fresh store from re-fetch
            System.setProperty(Properties.X509_CRL_CACHE_TTL, "1");
            try
            {
                Thread.sleep(1200);
                PKIXCRLStore c = CrlCache.getCrl(certFact, now, dp);
                assertTrue("TTL did not trigger re-fetch", a != c);

                // 4) within TTL window again — same fresh instance
                PKIXCRLStore d = CrlCache.getCrl(certFact, now, dp);
                assertTrue("expected cache hit within TTL", c == d);
            }
            finally
            {
                System.getProperties().remove(Properties.X509_CRL_CACHE_TTL);
            }
        }
        finally
        {
            tmp.delete();
        }
    }
}
