package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Arrays;

/**
 * Parsing and encoding of a <i>CertificateRequest</i> struct from RFC 4346:
 * <pre>
 * struct {
 *     ClientCertificateType certificate_types&lt;1..2^8-1&gt;;
 *     DistinguishedName certificate_authorities&lt;3..2^16-1&gt;;
 * } CertificateRequest;
 * </pre>
 * Updated for RFC 5246:
 * <pre>
 * struct {
 *     ClientCertificateType certificate_types<1..2^8-1>;
 *     SignatureAndHashAlgorithm supported_signature_algorithms<2^16-1>;
 *     DistinguishedName certificate_authorities<0..2^16-1>;
 * } CertificateRequest;
 * </pre>
 * Revised for RFC 8446:
 * <pre>
 * struct {
 *     opaque certificate_request_context<0..2^8-1>;
 *     Extension extensions<2..2^16-1>;
 * } CertificateRequest;
 * </pre>
 *
 * @see ClientCertificateType
 * @see X500Name
 */
public class CertificateRequest
{
    private static Vector checkSupportedSignatureAlgorithms(Vector supportedSignatureAlgorithms, short alertDescription)
        throws IOException
    {
        if (null == supportedSignatureAlgorithms)
        {
            throw new TlsFatalAlert(alertDescription, "'signature_algorithms' is required");
        }
        return supportedSignatureAlgorithms;
    }

    protected final byte[] certificateRequestContext;
    protected final short[] certificateTypes;
    protected final Vector supportedSignatureAlgorithms;
    protected final Vector supportedSignatureAlgorithmsCert;
    protected final Vector certificateAuthorities;

    /**
     * @param certificateTypes       see {@link ClientCertificateType} for valid constants.
     * @param certificateAuthorities a {@link Vector} of {@link X500Name}.
     */
    public CertificateRequest(short[] certificateTypes, Vector supportedSignatureAlgorithms,
        Vector certificateAuthorities)
    {
        this(null, certificateTypes, supportedSignatureAlgorithms, null, certificateAuthorities);
    }

    // TODO[tls13] Prefer to manage the certificateRequestContext internally only? 
    public CertificateRequest(byte[] certificateRequestContext, Vector supportedSignatureAlgorithms,
        Vector supportedSignatureAlgorithmsCert, Vector certificateAuthorities) throws IOException
    {
        /*
         * TODO[tls13] Removed certificateTypes, added certificate_request_context, added extensions
         * (required: signature_algorithms, optional: status_request, signed_certificate_timestamp,
         * certificate_authorities, oid_filters, signature_algorithms_cert)
         */

        this(certificateRequestContext, null,
            checkSupportedSignatureAlgorithms(supportedSignatureAlgorithms, AlertDescription.internal_error),
            supportedSignatureAlgorithmsCert, certificateAuthorities);
    }

    private CertificateRequest(byte[] certificateRequestContext, short[] certificateTypes, Vector supportedSignatureAlgorithms,
        Vector supportedSignatureAlgorithmsCert, Vector certificateAuthorities)
    {
        if (null != certificateRequestContext && !TlsUtils.isValidUint8(certificateRequestContext.length))
        {
            throw new IllegalArgumentException("'certificateRequestContext' cannot be longer than 255");
        }
        if (null != certificateTypes
            && (certificateTypes.length < 1 || !TlsUtils.isValidUint8(certificateTypes.length)))
        {
            throw new IllegalArgumentException("'certificateTypes' should have length from 1 to 255");
        }

        this.certificateRequestContext = TlsUtils.clone(certificateRequestContext);
        this.certificateTypes = certificateTypes;
        this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
        this.supportedSignatureAlgorithmsCert = supportedSignatureAlgorithmsCert;
        this.certificateAuthorities = certificateAuthorities;
    }

    public byte[] getCertificateRequestContext()
    {
        return TlsUtils.clone(certificateRequestContext);
    }

    /**
     * @return an array of certificate types
     * @see ClientCertificateType
     */
    public short[] getCertificateTypes()
    {
        return certificateTypes;
    }

    /**
     * @return a {@link Vector} of {@link SignatureAndHashAlgorithm} (or null before TLS 1.2).
     */
    public Vector getSupportedSignatureAlgorithms()
    {
        return supportedSignatureAlgorithms;
    }

    /**
     * @return an optional {@link Vector} of {@link SignatureAndHashAlgorithm}. May be non-null from
     *         TLS 1.3 onwards.
     */
    public Vector getSupportedSignatureAlgorithmsCert()
    {
        return supportedSignatureAlgorithmsCert;
    }

    /**
     * @return a {@link Vector} of {@link X500Name}
     */
    public Vector getCertificateAuthorities()
    {
        return certificateAuthorities;
    }

    public boolean hasCertificateRequestContext(byte[] certificateRequestContext)
    {
        return Arrays.areEqual(this.certificateRequestContext, certificateRequestContext);
    }

    /**
     * Encode this {@link CertificateRequest} to an {@link OutputStream}.
     *
     * @param output the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(TlsContext context, OutputStream output)
        throws IOException
    {
        final ProtocolVersion negotiatedVersion = context.getServerVersion();
        final boolean isTLSv12 = TlsUtils.isTLSv12(negotiatedVersion);
        final boolean isTLSv13 = TlsUtils.isTLSv13(negotiatedVersion);

        if (isTLSv13 != (null != certificateRequestContext) ||
            isTLSv13 != (null == certificateTypes) ||
            isTLSv12 != (null != supportedSignatureAlgorithms) ||
            !isTLSv13 && (null != supportedSignatureAlgorithmsCert))
        {
            throw new IllegalStateException();
        }

        if (isTLSv13)
        {
            TlsUtils.writeOpaque8(certificateRequestContext, output);

            Hashtable extensions = new Hashtable();
            TlsExtensionsUtils.addSignatureAlgorithmsExtension(extensions, supportedSignatureAlgorithms);

            if (null != supportedSignatureAlgorithmsCert)
            {
                TlsExtensionsUtils.addSignatureAlgorithmsCertExtension(extensions, supportedSignatureAlgorithmsCert);
            }

            if (null != certificateAuthorities)
            {
                TlsExtensionsUtils.addCertificateAuthoritiesExtension(extensions, certificateAuthorities);
            }

            byte[] extEncoding = TlsProtocol.writeExtensionsData(extensions);

            TlsUtils.writeOpaque16(extEncoding, output);
            return;
        }

        TlsUtils.writeUint8ArrayWithUint8Length(certificateTypes, output);

        if (isTLSv12)
        {
            // TODO Check whether SignatureAlgorithm.anonymous is allowed here
            TlsUtils.encodeSupportedSignatureAlgorithms(supportedSignatureAlgorithms, output);
        }

        if (certificateAuthorities == null || certificateAuthorities.isEmpty())
        {
            TlsUtils.writeUint16(0, output);
        }
        else
        {
            Vector derEncodings = new Vector(certificateAuthorities.size());

            int totalLength = 0;
            for (int i = 0; i < certificateAuthorities.size(); ++i)
            {
                X500Name certificateAuthority = (X500Name)certificateAuthorities.elementAt(i);
                byte[] derEncoding = certificateAuthority.getEncoded(ASN1Encoding.DER);
                derEncodings.addElement(derEncoding);
                totalLength += derEncoding.length + 2;
            }

            TlsUtils.checkUint16(totalLength);
            TlsUtils.writeUint16(totalLength, output);

            for (int i = 0; i < derEncodings.size(); ++i)
            {
                byte[] derEncoding = (byte[])derEncodings.elementAt(i);
                TlsUtils.writeOpaque16(derEncoding, output);
            }
        }
    }

    /**
     * Parse a {@link CertificateRequest} from an {@link InputStream}.
     * 
     * @param context
     *            the {@link TlsContext} of the current connection.
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link CertificateRequest} object.
     * @throws IOException
     */
    public static CertificateRequest parse(TlsContext context, InputStream input)
        throws IOException
    {
        final ProtocolVersion negotiatedVersion = context.getServerVersion();
        final boolean isTLSv13 = TlsUtils.isTLSv13(negotiatedVersion);

        if (isTLSv13)
        {
            byte[] certificateRequestContext = TlsUtils.readOpaque8(input);

            /*
             * TODO[tls13] required: signature_algorithms; optional: status_request,
             * signed_certificate_timestamp, certificate_authorities, oid_filters,
             * signature_algorithms_cert
             */

            byte[] extEncoding = TlsUtils.readOpaque16(input);

            Hashtable extensions = TlsProtocol.readExtensionsData13(HandshakeType.certificate_request, extEncoding);

            Vector supportedSignatureAlgorithms = checkSupportedSignatureAlgorithms(
                TlsExtensionsUtils.getSignatureAlgorithmsExtension(extensions), AlertDescription.missing_extension);
            Vector supportedSignatureAlgorithmsCert = TlsExtensionsUtils
                .getSignatureAlgorithmsCertExtension(extensions);
            Vector certificateAuthorities = TlsExtensionsUtils.getCertificateAuthoritiesExtension(extensions);

            return new CertificateRequest(certificateRequestContext, supportedSignatureAlgorithms,
                supportedSignatureAlgorithmsCert, certificateAuthorities);
        }

        final boolean isTLSv12 = TlsUtils.isTLSv12(negotiatedVersion);

        short[] certificateTypes = TlsUtils.readUint8ArrayWithUint8Length(input, 1);

        Vector supportedSignatureAlgorithms = null;
        if (isTLSv12)
        {
            supportedSignatureAlgorithms = TlsUtils.parseSupportedSignatureAlgorithms(input);
        }

        Vector certificateAuthorities = null;
        {
            byte[] certAuthData = TlsUtils.readOpaque16(input);
            if (certAuthData.length > 0)
            {
                certificateAuthorities = new Vector();
                ByteArrayInputStream bis = new ByteArrayInputStream(certAuthData);
                do
                {
                    byte[] derEncoding = TlsUtils.readOpaque16(bis, 1);
                    ASN1Primitive asn1 = TlsUtils.readDERObject(derEncoding);
                    certificateAuthorities.addElement(X500Name.getInstance(asn1));
                }
                while (bis.available() > 0);
            }
        }

        return new CertificateRequest(certificateTypes, supportedSignatureAlgorithms, certificateAuthorities);
    }
}
