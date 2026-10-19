package org.bouncycastle.x509;

import java.net.URLConnection;

/**
 * Sets the connect and read timeouts {@link PKIXCertPathReviewer} applies to a CRL distribution
 * point fetch. This is a version hook: the jdk1.4 build carries a twin that sets nothing, as
 * URLConnection.setConnectTimeout and setReadTimeout are Java 5. Keep the two in step.
 */
class URLConnectionTimeouts
{
    // in milliseconds, as CrlCache
    private static final int TIMEOUT = 15000;

    static void set(URLConnection conn)
    {
        conn.setConnectTimeout(TIMEOUT);
        conn.setReadTimeout(TIMEOUT);
    }
}
