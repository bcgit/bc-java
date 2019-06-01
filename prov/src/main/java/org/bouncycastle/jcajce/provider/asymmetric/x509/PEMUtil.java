package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;

class PEMUtil
{
    /**
     * Boundary class. Keeps track of the required header/footer pair for the
     * current PEM object.
     *
     */
    private class Boundaries
    {
        private final String _header;
        private final String _footer;

        private Boundaries(String type)
        {
            this._header = "-----BEGIN " + type + "-----";
            this._footer = "-----END " + type + "-----";
        }

        public boolean isTheExpectedHeader(String line)
        {
            return line.startsWith(_header);
        }

        public boolean isTheExpectedFooter(String line)
        {
            return line.startsWith(_footer);
        }
    }

    private final Boundaries[] _supportedBoundaries;

    PEMUtil(String type)
    {
        _supportedBoundaries = new Boundaries[]
        { new Boundaries(type), new Boundaries("X509 " + type),
                new Boundaries("PKCS7") };
    }

    private String readLine(InputStream in) throws IOException
    {
        int c;
        StringBuffer l = new StringBuffer();

        do
        {
            while (((c = in.read()) != '\r') && c != '\n' && (c >= 0))
            {
                l.append((char) c);
            }
        }
        while (c >= 0 && l.length() == 0);
   
        if (c < 0)
        {
            // make sure to return the read bytes if the end of file is encountered
            if (l.length() == 0)
            {
                return null;
            }
            return l.toString();
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

    /**
     * Returns a {@link Boundaries} object representing the passed in boundary
     * string.
     * 
     * @param line the boundary string
     * @return the {@link Boundaries} object corresponding to the given boundary
     *         string or <code>null</code> if the passed in string is not a valid
     *         boundary.
     */
    private Boundaries getBoundaries(String line)
    {
        for (int i = 0; i != _supportedBoundaries.length; i++)
        {
            Boundaries boundary = _supportedBoundaries[i];
            
            if (boundary.isTheExpectedHeader(line) || boundary.isTheExpectedFooter(line))
            {
                return boundary;
            }
        }

        return null;
    }

    ASN1Sequence readPEMObject(
        InputStream in)
        throws IOException
    {
        String line;
        StringBuffer pemBuf = new StringBuffer();

        Boundaries header = null;

        while (header == null && (line = readLine(in)) != null)
        {
            header = getBoundaries(line);
            if (header != null && !header.isTheExpectedHeader(line))
            {
                throw new IOException("malformed PEM data: found footer where header was expected");
            }
        }

        if (header == null)
        {
            throw new IOException("malformed PEM data: no header found");
        }

        Boundaries footer = null;

        while (footer == null && (line = readLine(in)) != null)
        {
            footer = getBoundaries(line);
            if (footer != null)
            {
                if (!header.isTheExpectedFooter(line))
                {
                    throw new IOException("malformed PEM data: header/footer mismatch");
                }
            }
            else
            {
                pemBuf.append(line);
            }
        }

        if (footer == null)
        {
            throw new IOException("malformed PEM data: no footer found");
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
