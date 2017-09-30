package com.github.gv2011.asn1.util.io.pem;

import static com.github.gv2011.util.ex.Exceptions.call;

import java.io.BufferedReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import com.github.gv2011.asn1.util.encoders.Base64;

/**
 * A generic PEM reader, based on the format outlined in RFC 1421
 */
public class PemReader
    extends BufferedReader
{
    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";

    public PemReader(final Reader reader)
    {
        super(reader);
    }



    @Override
    public String readLine(){
      return call(super::readLine);
    }



    public PemObject readPemObject()
    {
        String line = readLine();

        while (line != null && !line.startsWith(BEGIN))
        {
            line = readLine();
        }

        if (line != null)
        {
            line = line.substring(BEGIN.length());
            final int index = line.indexOf('-');
            final String type = line.substring(0, index);

            if (index > 0)
            {
                return loadObject(type);
            }
        }

        return null;
    }

    private PemObject loadObject(final String type)
    {
        String          line;
        final String          endMarker = END + type;
        final StringBuffer    buf = new StringBuffer();
        final List<PemHeader>            headers = new ArrayList<>();

        while ((line = readLine()) != null)
        {
            if (line.indexOf(":") >= 0)
            {
                final int index = line.indexOf(':');
                final String hdr = line.substring(0, index);
                final String value = line.substring(index + 1).trim();

                headers.add(new PemHeader(hdr, value));

                continue;
            }

            if (line.indexOf(endMarker) != -1)
            {
                break;
            }

            buf.append(line.trim());
        }

        if (line == null)
        {
            throw new PemGenerationException(endMarker + " not found");
        }

        return new PemObject(type, headers, Base64.decode(buf.toString()));
    }

}
