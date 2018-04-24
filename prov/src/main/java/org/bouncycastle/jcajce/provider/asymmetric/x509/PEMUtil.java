package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;

class PEMUtil
{
    private final String _header1;
    private final String _header2;
    private final String _header3;
    private final String _footer1;
    private final String _footer2;
    private final String _footer3;

    PEMUtil(
        String type)
    {
        _header1 = "-----BEGIN " + type + "-----";
        _header2 = "-----BEGIN X509 " + type + "-----";
        _header3 = "-----BEGIN PKCS7-----";
        _footer1 = "-----END " + type + "-----";
        _footer2 = "-----END X509 " + type + "-----";
        _footer3 = "-----END PKCS7-----";
    }

    private String readLine(
        InputStream in)
        throws IOException
    {
        int             c;
        StringBuffer l = new StringBuffer();

        do
        {
            while (((c = in.read()) != '\r') && c != '\n' && (c >= 0))
            {
                l.append((char)c);
            }
        }
        while (c >= 0 && l.length() == 0);

        if (c < 0)
        {
            return null;
        }

        // make sure we parse to end of line.
        if (c == '\r')
        {
            // a '\n' may follow
            in.mark(1);
            if (((c = in.read()) == '\n'))
            {
                in.mark(1);
            }

            if (c > 0)
            {
                in.reset();
            }
        }

        return l.toString();
    }

    ASN1Sequence readPEMObject(
        InputStream in)
        throws IOException
    {
        String line;
        StringBuffer pemBuf = new StringBuffer();

        while ((line = readLine(in)) != null)
        {
            if (line.startsWith(_header1) || line.startsWith(_header2) || line.startsWith(_header3))
            {
                break;
            }
        }

        while ((line = readLine(in)) != null)
        {
            if (line.startsWith(_footer1) || line.startsWith(_footer2) || line.startsWith(_footer3))
            {
                break;
            }

            pemBuf.append(line);
        }

        if (pemBuf.length() != 0)
        {
            try
            {
                return ASN1Sequence.getInstance(Base64.decode(pemBuf.toString()));
            }
            catch (Exception e)
            {
                throw new IOException("malformed PEM data encountered");
            }
        }

        return null;
    }
}
