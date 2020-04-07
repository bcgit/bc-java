package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ocsp.OCSPResponse;

public class CertificateStatus
{
    protected short statusType;
    protected Object response;

    public CertificateStatus(short statusType, Object response)
    {
        if (!isCorrectType(statusType, response))
        {
            throw new IllegalArgumentException("'response' is not an instance of the correct type");
        }
        
        this.statusType = statusType;
        this.response = response;
    }

    public short getStatusType()
    {
        return statusType;
    }

    public Object getResponse()
    {
        return response;
    }

    public OCSPResponse getOCSPResponse()
    {
        if (!isCorrectType(CertificateStatusType.ocsp, response))
        {
            throw new IllegalStateException("'response' is not an OCSPResponse");
        }
        return (OCSPResponse)response;
    }

    /**
     * @return a {@link Vector} of (possibly null) {@link OCSPResponse}.
     */
    public Vector getOCSPResponseList()
    {
        if (!isCorrectType(CertificateStatusType.ocsp_multi, response))
        {
            throw new IllegalStateException("'response' is not an OCSPResponseList");
        }
        return (Vector)response;
    }

    /**
     * Encode this {@link CertificateStatus} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        TlsUtils.writeUint8(statusType, output);

        switch (statusType)
        {
        case CertificateStatusType.ocsp:
        {
            OCSPResponse ocspResponse = (OCSPResponse)response;
            byte[] derEncoding = ocspResponse.getEncoded(ASN1Encoding.DER);
            TlsUtils.writeOpaque24(derEncoding, output);
            break;
        }
        case CertificateStatusType.ocsp_multi:
        {
            Vector ocspResponseList = (Vector)response;
            int count = ocspResponseList.size();

            Vector derEncodings = new Vector(count);
            long totalLength = 0;
            for (int i = 0; i < count; ++i)
            {
                OCSPResponse ocspResponse = (OCSPResponse)ocspResponseList.elementAt(i);
                if (ocspResponse == null)
                {
                    derEncodings.addElement(TlsUtils.EMPTY_BYTES);
                }
                else
                {
                    byte[] derEncoding = ocspResponse.getEncoded(ASN1Encoding.DER);
                    derEncodings.addElement(derEncoding);
                    totalLength += derEncoding.length;
                }
                totalLength += 3;
            }

            TlsUtils.checkUint24(totalLength);
            TlsUtils.writeUint24((int)totalLength, output);

            for (int i = 0; i < count; ++i)
            {
                byte[] derEncoding = (byte[])derEncodings.elementAt(i);
                TlsUtils.writeOpaque24(derEncoding, output);
            }

            break;
        }
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    /**
     * Parse a {@link CertificateStatus} from an {@link InputStream}.
     * 
     * @param context
     *            the {@link TlsContext} of the current connection.
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link CertificateStatus} object.
     * @throws IOException
     */
    public static CertificateStatus parse(TlsContext context, InputStream input) throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        Certificate peerCertificate = securityParameters.getPeerCertificate();
        if (null == peerCertificate || peerCertificate.isEmpty()
            || CertificateType.X509 != peerCertificate.getCertificateType())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        final int certificateCount = peerCertificate.getLength();
        final int statusRequestVersion = securityParameters.getStatusRequestVersion();

        short status_type = TlsUtils.readUint8(input);
        Object response;

        switch (status_type)
        {
        case CertificateStatusType.ocsp:
        {
            requireStatusRequestVersion(1, statusRequestVersion);

            byte[] derEncoding = TlsUtils.readOpaque24(input, 1);
            ASN1Primitive derObject = TlsUtils.readDERObject(derEncoding);
            response = OCSPResponse.getInstance(derObject);
            break;
        }
        case CertificateStatusType.ocsp_multi:
        {
            requireStatusRequestVersion(2, statusRequestVersion);

            byte[] ocsp_response_list = TlsUtils.readOpaque24(input, 1);
            ByteArrayInputStream buf = new ByteArrayInputStream(ocsp_response_list);

            Vector ocspResponseList = new Vector();
            while (buf.available() > 0)
            {
                if (ocspResponseList.size() >= certificateCount)
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                int length = TlsUtils.readUint24(buf);
                if (length < 1)
                {
                    ocspResponseList.addElement(null);
                }
                else
                {
                    byte[] derEncoding = TlsUtils.readFully(length, buf);
                    ASN1Primitive derObject = TlsUtils.readDERObject(derEncoding);
                    OCSPResponse ocspResponse = OCSPResponse.getInstance(derObject);
                    ocspResponseList.addElement(ocspResponse);
                }
            }

            ocspResponseList.trimToSize();
            response = ocspResponseList;
            break;
        }
        default:
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        return new CertificateStatus(status_type, response);
    }

    protected static boolean isCorrectType(short statusType, Object response)
    {
        switch (statusType)
        {
        case CertificateStatusType.ocsp:
            return response instanceof OCSPResponse;
        case CertificateStatusType.ocsp_multi:
            return isOCSPResponseList(response);
        default:
            throw new IllegalArgumentException("'statusType' is an unsupported CertificateStatusType");
        }
    }

    protected static boolean isOCSPResponseList(Object response)
    {
        if (!(response instanceof Vector))
        {
            return false;
        }
        Vector v = (Vector)response;
        int count = v.size();
        if (count < 1)
        {
            return false;
        }
        for (int i = 0; i < count; ++i)
        {
            Object e = v.elementAt(i);
            if (null != e && !(e instanceof OCSPResponse))
            {
                return false;
            }
        }
        return true;
    }

    protected static void requireStatusRequestVersion(int minVersion, int statusRequestVersion)
        throws IOException
    {
        if (statusRequestVersion < minVersion)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
    }
}
