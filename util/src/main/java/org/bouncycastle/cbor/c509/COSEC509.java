package org.bouncycastle.cbor.c509;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.CBORType;

/**
 * The COSE_C509 structure (Section 3.4 of draft-ietf-cose-cbor-encoded-cert-20):
 * <pre>
 * COSE_C509 = C509CertData / [ 2* C509CertData ]
 * C509CertData = bytes .cbor C509Certificate
 * </pre>
 * a single certificate, or an array of two or more, each wrapped in a byte string so
 * a parser can skip over individual certificates.
 */
public final class COSEC509
{
    /**
     * Encode a bag or chain of certificates as a COSE_C509 structure. One certificate
     * is encoded as a bare C509CertData; two or more as an array.
     */
    public static byte[] encode(C509Certificate[] certificates)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        encodeTo(new CBOREncoder(bOut), certificates);
        return bOut.toByteArray();
    }

    static void encodeTo(CBOREncoder out, C509Certificate[] certificates)
        throws IOException
    {
        if (certificates.length == 0)
        {
            throw new IllegalArgumentException("COSE_C509 must hold at least one certificate");
        }
        if (certificates.length == 1)
        {
            out.writeByteString(certificates[0].getEncoded());
            return;
        }
        out.writeArrayHeader(certificates.length);
        for (int i = 0; i != certificates.length; i++)
        {
            out.writeByteString(certificates[i].getEncoded());
        }
    }

    /**
     * Decode a COSE_C509 structure.
     */
    public static C509Certificate[] decode(byte[] encoding)
        throws IOException
    {
        CBORDecoder in = new CBORDecoder(encoding);
        C509Certificate[] certificates = decode(in);
        in.expectEnd();
        return certificates;
    }

    static C509Certificate[] decode(CBORDecoder in)
        throws IOException
    {
        if (in.peekMajorType() == CBORType.BYTE_STRING)
        {
            return new C509Certificate[]{ C509Certificate.getInstance(in.readByteString()) };
        }
        int count = in.readArrayHeader();
        if (count < 2)
        {
            throw new IOException("COSE_C509 array must hold at least 2 certificates");
        }
        C509Certificate[] certificates = new C509Certificate[count];
        for (int i = 0; i != count; i++)
        {
            certificates[i] = C509Certificate.getInstance(in.readByteString());
        }
        return certificates;
    }

    private COSEC509()
    {
    }
}
