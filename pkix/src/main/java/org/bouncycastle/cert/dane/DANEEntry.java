package org.bouncycastle.cert.dane;

import java.io.IOException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Arrays;

/**
 * Carrier class for a DANE entry.
 */
public class DANEEntry
{
    public static final int CERT_USAGE_CA = 0;
    public static final int CERT_USAGE_PKIX_VALIDATE = 1;
    public static final int CERT_USAGE_TRUST_ANCHOR = 2;
    public static final int CERT_USAGE_ACCEPT = 3;

    static final int CERT_USAGE = 0;
    static final int SELECTOR = 1;
    static final int MATCHING_TYPE = 2;

    private final String domainName;
    private final byte[] flags;
    private final X509CertificateHolder certHolder;

    DANEEntry(String domainName, byte[] flags, X509CertificateHolder certHolder)
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
     * Return the full data string as it would appear in the DNS record - flags + encoding
     *
     * @return byte array representing the full data string.
     * @throws IOException if there is an issue encoding the certificate inside this entry.
     */
    public byte[] getRDATA()
        throws IOException
    {
        byte[] certEnc = certHolder.getEncoded();
        byte[] data = new byte[flags.length + certEnc.length];

        System.arraycopy(flags, 0, data, 0, flags.length);
        System.arraycopy(certEnc, 0, data, flags.length, certEnc.length);

        return data;
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
        return ((data[CERT_USAGE] >= 0 || data[CERT_USAGE] <= 3)&& data[SELECTOR] == 0 && data[MATCHING_TYPE] == 0);
    }
}
