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

    /**
     * Create an entry from the RDATA of a DNS record.
     *
     * @param domainName the owner name of the record.
     * @param data the record's RDATA: the three flag bytes followed by the certificate encoding.
     * @throws IOException if the flags do not describe a full certificate entry (see {@link #isValidCertificate(byte[])})
     * or the certificate encoding is malformed.
     */
    public DANEEntry(String domainName, byte[] data)
        throws IOException
    {
        this(domainName, flagsOf(data), new X509CertificateHolder(Arrays.copyOfRange(data, 3, data.length)));
    }

    private static byte[] flagsOf(byte[] data)
        throws IOException
    {
        if (!isValidCertificate(data))
        {
            throw new IOException("DANE record is not a full certificate entry");
        }

        return Arrays.copyOfRange(data, 0, 3);
    }

    /**
     * Return the three flag bytes: certificate usage, selector and matching type.
     *
     * @return a copy of the flag bytes.
     */
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

    /**
     * Return the owner name of the DNS record this entry came from or is destined for.
     *
     * @return the entry's fully qualified domain name.
     */
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
        // a record shorter than the three flag bytes cannot be a certificate entry
        if (data == null || data.length < 3)
        {
            return false;
        }
        // TODO: perhaps validate ASN.1 data as well...
        return ((data[CERT_USAGE] >= 0 && data[CERT_USAGE] <= 3) && data[SELECTOR] == 0 && data[MATCHING_TYPE] == 0);
    }
}
