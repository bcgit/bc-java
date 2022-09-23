package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;

/**
 * Parsing and encoding of a <i>Certificate</i> struct from RFC 4346.
 * <pre>
 * opaque ASN.1Cert&lt;2^24-1&gt;;
 *
 * struct {
 *     ASN.1Cert certificate_list&lt;0..2^24-1&gt;;
 * } Certificate;
 * </pre>
 *
 * @see org.bouncycastle.asn1.x509.Certificate
 */
public class Certificate
{
    private static final TlsCertificate[] EMPTY_CERTS = new TlsCertificate[0];
    private static final CertificateEntry[] EMPTY_CERT_ENTRIES = new CertificateEntry[0];

    public static final Certificate EMPTY_CHAIN = new Certificate(EMPTY_CERTS);
    public static final Certificate EMPTY_CHAIN_TLS13 = new Certificate(TlsUtils.EMPTY_BYTES, EMPTY_CERT_ENTRIES);

    public static class ParseOptions
    {
        private int maxChainLength = Integer.MAX_VALUE;
        private short certificateType = CertificateType.X509;

        public int getMaxChainLength()
        {
            return maxChainLength;
        }

        public ParseOptions setMaxChainLength(int maxChainLength)
        {
            this.maxChainLength = maxChainLength;
            return this;
        }

        public short getCertificateType()
        {
            return certificateType;
        }

        /**
         * Set the {@link CertificateType} according to the IANA TLS Certificate Types registry
         */
        public ParseOptions setCertificateType(short certificateType)
        {
            this.certificateType = certificateType;
            return this;
        }        
    }

    private static CertificateEntry[] convert(TlsCertificate[] certificateList)
    {
        if (TlsUtils.isNullOrContainsNull(certificateList))
        {
            throw new NullPointerException("'certificateList' cannot be null or contain any nulls");
        }

        int count = certificateList.length;
        CertificateEntry[] result = new CertificateEntry[count];
        for (int i = 0; i < count; ++i)
        {
            result[i] = new CertificateEntry(certificateList[i], null);
        }
        return result;
    }

    protected final byte[] certificateRequestContext;
    protected final CertificateEntry[] certificateEntryList;
    protected final short certificateType;

    public Certificate(TlsCertificate[] certificateList)
    {
        this(null, convert(certificateList));
    }

    public Certificate(byte[] certificateRequestContext, CertificateEntry[] certificateEntryList)
    {
        this(CertificateType.X509, certificateRequestContext, certificateEntryList);
    }

    // TODO[tls13] Prefer to manage the certificateRequestContext internally only?
    public Certificate(short certificateType, byte[] certificateRequestContext, CertificateEntry[] certificateEntryList)
    {
        if (null != certificateRequestContext && !TlsUtils.isValidUint8(certificateRequestContext.length))
        {
            throw new IllegalArgumentException("'certificateRequestContext' cannot be longer than 255");
        }
        if (TlsUtils.isNullOrContainsNull(certificateEntryList))
        {
            throw new NullPointerException("'certificateEntryList' cannot be null or contain any nulls");
        }

        this.certificateRequestContext = TlsUtils.clone(certificateRequestContext);
        this.certificateEntryList = certificateEntryList;
        this.certificateType = certificateType;
    }

    public byte[] getCertificateRequestContext()
    {
        return TlsUtils.clone(certificateRequestContext);
    }

    /**
     * @return an array of {@link org.bouncycastle.asn1.x509.Certificate} representing a certificate
     *         chain.
     */
    public TlsCertificate[] getCertificateList()
    {
        return cloneCertificateList();
    }

    public TlsCertificate getCertificateAt(int index)
    {
        return certificateEntryList[index].getCertificate();
    }

    public CertificateEntry getCertificateEntryAt(int index)
    {
        return certificateEntryList[index];
    }

    public CertificateEntry[] getCertificateEntryList()
    {
        return cloneCertificateEntryList();
    }

    public short getCertificateType()
    {
        return certificateType;
    }

    public int getLength()
    {
        return certificateEntryList.length;
    }

    /**
     * @return <code>true</code> if this certificate chain contains no certificates, or
     *         <code>false</code> otherwise.
     */
    public boolean isEmpty()
    {
        return certificateEntryList.length == 0;
    }

    /**
     * Encode this {@link Certificate} to an {@link OutputStream}, and optionally calculate the
     * "end point hash" (per RFC 5929's tls-server-end-point binding).
     *
     * @param messageOutput the {@link OutputStream} to encode to.
     * @param endPointHashOutput the {@link OutputStream} to write the "end point hash" (or null).
     * @throws IOException
     */
    public void encode(TlsContext context, OutputStream messageOutput, OutputStream endPointHashOutput)
        throws IOException
    {
        final boolean isTLSv13 = TlsUtils.isTLSv13(context);

        if ((null != certificateRequestContext) != isTLSv13)
        {
            throw new IllegalStateException();
        }

        if (isTLSv13)
        {
            TlsUtils.writeOpaque8(certificateRequestContext, messageOutput);
        }

        int count = certificateEntryList.length;
        Vector certEncodings = new Vector(count);
        Vector extEncodings = isTLSv13 ? new Vector(count) : null;

        long totalLength = 0;
        for (int i = 0; i < count; ++i)
        {
            CertificateEntry entry = certificateEntryList[i];
            TlsCertificate cert = entry.getCertificate();
            byte[] derEncoding = cert.getEncoded();

            if (i == 0 && endPointHashOutput != null)
            {
                calculateEndPointHash(context, cert, derEncoding, endPointHashOutput);
            }

            certEncodings.addElement(derEncoding);
            totalLength += derEncoding.length;
            totalLength += 3;

            if (isTLSv13)
            {
                Hashtable extensions = entry.getExtensions();
                byte[] extEncoding = (null == extensions)
                    ?   TlsUtils.EMPTY_BYTES
                    :   TlsProtocol.writeExtensionsData(extensions);

                extEncodings.addElement(extEncoding);
                totalLength += extEncoding.length;
                totalLength += 2;
            }
        }

        // RFC 7250 indicates the raw key is not wrapped in a cert list like X509 is
        // but RFC 8446 wraps it in a CertificateEntry, which is inside certificate_list
        if (isTLSv13 || certificateType != CertificateType.RawPublicKey)
        {
            TlsUtils.checkUint24(totalLength);
            TlsUtils.writeUint24((int)totalLength, messageOutput);
        }

        for (int i = 0; i < count; ++i)
        {
            byte[] certEncoding = (byte[])certEncodings.elementAt(i);
            TlsUtils.writeOpaque24(certEncoding, messageOutput);

            if (isTLSv13)
            {
                byte[] extEncoding = (byte[])extEncodings.elementAt(i);
                TlsUtils.writeOpaque16(extEncoding, messageOutput);
            }
        }
    }

    /**
     * Parse a {@link Certificate} from an {@link InputStream}.
     *
     * @param context
     *            the {@link TlsContext} of the current connection.
     * @param messageInput
     *            the {@link InputStream} to parse from.
     * @param endPointHashOutput the {@link OutputStream} to write the "end point hash" (or null).
     * @return a {@link Certificate} object.
     * @throws IOException
     * @deprecated Use version taking a {@link ParseOptions} argument instead. 
     */
    public static Certificate parse(TlsContext context, InputStream messageInput, OutputStream endPointHashOutput)
        throws IOException
    {
        return parse(new ParseOptions(), context, messageInput, endPointHashOutput);
    }

    /**
     * Parse a {@link Certificate} from an {@link InputStream}.
     *
     * @param options
     *            the {@link ParseOptions} to apply during parsing.  
     * @param context
     *            the {@link TlsContext} of the current connection.
     * @param messageInput
     *            the {@link InputStream} to parse from.
     * @param endPointHashOutput the {@link OutputStream} to write the "end point hash" (or null).
     * @return a {@link Certificate} object.
     * @throws IOException
     */
    public static Certificate parse(ParseOptions options, TlsContext context, InputStream messageInput,
        OutputStream endPointHashOutput) throws IOException
    {
        final SecurityParameters securityParameters = context.getSecurityParameters();
        final boolean isTLSv13 = TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion());
        final short certType = options.getCertificateType();

        byte[] certificateRequestContext = null;
        if (isTLSv13)
        {
            certificateRequestContext = TlsUtils.readOpaque8(messageInput);
        }

        int totalLength = TlsUtils.readUint24(messageInput);
        if (totalLength == 0)
        {
            return !isTLSv13 ? EMPTY_CHAIN
                :  certificateRequestContext.length < 1 ? EMPTY_CHAIN_TLS13
                :  new Certificate(certType, certificateRequestContext, EMPTY_CERT_ENTRIES);
        }

        byte[] certListData = TlsUtils.readFully(totalLength, messageInput);
        ByteArrayInputStream buf = new ByteArrayInputStream(certListData);

        TlsCrypto crypto = context.getCrypto();
        int maxChainLength = Math.max(1, options.getMaxChainLength());

        Vector certificate_list = new Vector();
        while (buf.available() > 0)
        {
            if (certificate_list.size() >= maxChainLength)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error,
                    "Certificate chain longer than maximum (" + maxChainLength + ")");
            }

            // RFC 7250 indicates the raw key is not wrapped in a cert list like X509 is
            // but RFC 8446 wraps it in a CertificateEntry, which is inside certificate_list
            byte[] derEncoding;
            if (isTLSv13 || certType != CertificateType.RawPublicKey)
            {
                derEncoding = TlsUtils.readOpaque24(buf, 1);
            }
            else
            {
                derEncoding = certListData;
                buf.skip(totalLength);
            }

            TlsCertificate cert = crypto.createCertificate(certType, derEncoding);

            if (certificate_list.isEmpty() && endPointHashOutput != null)
            {
                calculateEndPointHash(context, cert, derEncoding, endPointHashOutput);
            }

            Hashtable extensions = null;
            if (isTLSv13)
            {
                byte[] extEncoding = TlsUtils.readOpaque16(buf);

                extensions = TlsProtocol.readExtensionsData13(HandshakeType.certificate, extEncoding);
            }

            certificate_list.addElement(new CertificateEntry(cert, extensions));
        }

        CertificateEntry[] certificateList = new CertificateEntry[certificate_list.size()];
        for (int i = 0; i < certificate_list.size(); i++)
        {
            certificateList[i] = (CertificateEntry)certificate_list.elementAt(i);
        }

        return new Certificate(certType, certificateRequestContext, certificateList);
    }

    protected static void calculateEndPointHash(TlsContext context, TlsCertificate cert, byte[] encoding,
        OutputStream output) throws IOException
    {
        byte[] endPointHash = TlsUtils.calculateEndPointHash(context, cert, encoding);
        if (endPointHash != null && endPointHash.length > 0)
        {
            output.write(endPointHash);
        }
    }

    protected TlsCertificate[] cloneCertificateList()
    {
        int count = certificateEntryList.length;
        if (0 == count)
        {
            return EMPTY_CERTS;
        }
        TlsCertificate[] result = new TlsCertificate[count];
        for (int i = 0; i < count; ++i)
        {
            result[i] = certificateEntryList[i].getCertificate();
        }
        return result;
    }

    protected CertificateEntry[] cloneCertificateEntryList()
    {
        int count = certificateEntryList.length;
        if (0 == count)
        {
            return EMPTY_CERT_ENTRIES;
        }
        CertificateEntry[] result = new CertificateEntry[count];
        System.arraycopy(certificateEntryList, 0, result, 0, count);
        return result;
    }
}
