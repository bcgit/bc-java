package org.bouncycastle.x509;

import java.net.URLConnection;

/**
 * Sets the connect and read timeouts {@link PKIXCertPathReviewer} applies to a CRL distribution
 * point fetch.
 * <p>
 * NOTE: jdk1.4 overlay. URLConnection.setConnectTimeout and setReadTimeout are Java 5, so this
 * build can set no timeout and the method does nothing. Keep the signature in step with base.
 */
class URLConnectionTimeouts
{
    static void set(URLConnection conn)
    {
    }
}
