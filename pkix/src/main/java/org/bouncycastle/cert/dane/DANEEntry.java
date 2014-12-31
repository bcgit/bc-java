package org.bouncycastle.cert.dane;

import java.io.IOException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Arrays;

/**
 * Carrier class for a DANE entry.
 */
public class DANEEntry
{
    private static final int CERT_USAGE = 0;
    private static final int SELECTOR = 1;
    private static final int MATCHING_TYPE = 2;

    private final String domainName;
    private final byte[] flags;
    private final X509CertificateHolder certHolder;

    private DANEEntry(String domainName, byte[] flags, X509CertificateHolder certHolder)
    {
        this.flags = flags;
        this.domainName = domainName;
        this.certHolder = certHolder;
    }

    public DANEEntry(String domainName, byte[] data)
        throws IOException
    {
        this(domainName, Arrays.copyOfRange(data, 0, 3), new X509CertificateHolder(Arrays.copyOfRange(data, 3, data.length)));
    }

    public byte[] getFlags()
    {
        return Arrays.clone(flags);
    }

    /**
     * Return the certificate associated with this entry.
     *
     * @return the entry's certificate.
     */
    public X509CertificateHolder getCertificate()
    {
        return certHolder;
    }

    public String getDomainName()
    {
        return domainName;
    }

    /**
     * Return true if the byte string has the correct flag bytes to indicate a certificate entry.
     *
     * @param data the byte string of interest.
     * @return true if flags indicate a valid certificate, false otherwise.
     */
    public static boolean isValidCertificate(byte[] data)
    {
        // TODO: perhaps validate ASN.1 data as well...
        return (data[CERT_USAGE] == 3 && data[SELECTOR] == 0 && data[MATCHING_TYPE] == 0);
    }
}
