package org.bouncycastle.pkix.jcajce;

import junit.framework.TestCase;
import org.bouncycastle.util.Properties;

/**
 * Which protocols the reviewer will fetch a CRL distribution point over. It used to downcast the
 * connection to HttpURLConnection behind an http/https test, so an ftp distribution point was
 * silently skipped - the defect github #1867 fixed in CrlCache - and the
 * org.bouncycastle.x509.CRLDP_protocols whitelist did not reach this path at all.
 * <p/>
 * The identical method in the provider's org.bouncycastle.x509.PKIXCertPathReviewer is kept in step
 * with this one.
 */
public class PKIXCertPathReviewerProtocolTest
    extends TestCase
{
    public void testDefaultProtocols()
    {
        assertTrue(PKIXCertPathReviewer.isPermittedProtocol("http"));
        assertTrue(PKIXCertPathReviewer.isPermittedProtocol("https"));
        assertTrue("ftp distribution point still skipped", PKIXCertPathReviewer.isPermittedProtocol("ftp"));

        // the reviewer reports on a path, it does not fetch through arbitrary URL handlers
        assertFalse(PKIXCertPathReviewer.isPermittedProtocol("file"));
        assertFalse(PKIXCertPathReviewer.isPermittedProtocol("jar"));
        assertFalse(PKIXCertPathReviewer.isPermittedProtocol("ldap"));
    }

    public void testWhitelistNarrowsAndIsCaseInsensitive()
    {
        System.setProperty(Properties.X509_CRLDP_PROTOCOLS, "http, HTTPS");
        try
        {
            assertTrue(PKIXCertPathReviewer.isPermittedProtocol("http"));
            assertTrue("whitelist entry not matched without regard to case",
                PKIXCertPathReviewer.isPermittedProtocol("https"));
            assertFalse("ftp permitted under an http/https whitelist",
                PKIXCertPathReviewer.isPermittedProtocol("ftp"));
        }
        finally
        {
            System.getProperties().remove(Properties.X509_CRLDP_PROTOCOLS);
        }

        // a whitelist may also widen to a protocol outside the default set
        System.setProperty(Properties.X509_CRLDP_PROTOCOLS, "file");
        try
        {
            assertTrue(PKIXCertPathReviewer.isPermittedProtocol("file"));
            assertFalse(PKIXCertPathReviewer.isPermittedProtocol("http"));
        }
        finally
        {
            System.getProperties().remove(Properties.X509_CRLDP_PROTOCOLS);
        }
    }
}
