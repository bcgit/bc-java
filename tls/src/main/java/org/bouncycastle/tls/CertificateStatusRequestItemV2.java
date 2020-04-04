package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Implementation of the RFC 6961 2.2. CertificateStatusRequestItemV2.
 */
public class CertificateStatusRequestItemV2
{
    protected short statusType;
    protected Object request;

    public CertificateStatusRequestItemV2(short statusType, Object request)
    {
        if (!isCorrectType(statusType, request))
        {
            throw new IllegalArgumentException("'request' is not an instance of the correct type");
        }

        this.statusType = statusType;
        this.request = request;
    }

    public short getStatusType()
    {
        return statusType;
    }

    public Object getRequest()
    {
        return request;
    }

    public OCSPStatusRequest getOCSPStatusRequest()
    {
        if (!(request instanceof OCSPStatusRequest))
        {
            throw new IllegalStateException("'request' is not an OCSPStatusRequest");
        }
        return (OCSPStatusRequest)request;
    }

    /**
     * Encode this {@link CertificateStatusRequestItemV2} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        TlsUtils.writeUint8(statusType, output);

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        switch (statusType)
        {
        case CertificateStatusType.ocsp:
        case CertificateStatusType.ocsp_multi:
            ((OCSPStatusRequest)request).encode(buf);
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        byte[] requestBytes = buf.toByteArray();
        TlsUtils.writeOpaque16(requestBytes, output);
    }

    /**
     * Parse a {@link CertificateStatusRequestItemV2} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link CertificateStatusRequestItemV2} object.
     * @throws IOException
     */
    public static CertificateStatusRequestItemV2 parse(InputStream input) throws IOException
    {
        short status_type = TlsUtils.readUint8(input);

        Object request;
        byte[] requestBytes = TlsUtils.readOpaque16(input);
        ByteArrayInputStream buf = new ByteArrayInputStream(requestBytes);
        switch (status_type)
        {
        case CertificateStatusType.ocsp:
        case CertificateStatusType.ocsp_multi:
            request = OCSPStatusRequest.parse(buf);
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        TlsProtocol.assertEmpty(buf);

        return new CertificateStatusRequestItemV2(status_type, request);
    }

    protected static boolean isCorrectType(short statusType, Object request)
    {
        switch (statusType)
        {
        case CertificateStatusType.ocsp:
        case CertificateStatusType.ocsp_multi:
            return request instanceof OCSPStatusRequest;
        default:
            throw new IllegalArgumentException("'statusType' is an unsupported CertificateStatusType");
        }
    }
}
