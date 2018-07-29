package org.bouncycastle.mime;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.Strings;

class MimeUtils
{
    static String readLine(InputStream src)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = src.read()) >= 0 && ch != '\r' && ch != '\n')
        {
            bOut.write(ch);
        }

        // TODO: deal with trailing '\n'

        if (ch < 0)
        {
            return null;
        }

        return Strings.fromUTF8ByteArray(bOut.toByteArray());
    }
}
