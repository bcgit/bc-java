package org.bouncycastle.gpg;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.util.io.Streams;

/**
 * Utility functions for looking a S-expression keys. This class will move when it finds a better home!
 * <p>
 * Format documented here:
 * http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=agent/keyformat.txt;h=42c4b1f06faf1bbe71ffadc2fee0fad6bec91a97;hb=refs/heads/master
 * </p>
 */
class SXprUtils
{
    private static int readLength(InputStream in, int ch)
        throws IOException
    {
        int len = ch - '0';

        while ((ch = in.read()) >= 0 && ch != ':')
        {
            len = len * 10 + ch - '0';
        }

        return len;
    }

    static String readString(InputStream in, int ch)
        throws IOException
    {
        int len = readLength(in, ch);

        char[] chars = new char[len];

        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)in.read();
        }

        return new String(chars);
    }

    static byte[] readBytes(InputStream in, int ch)
        throws IOException
    {
        int len = readLength(in, ch);

        byte[] data = new byte[len];

        Streams.readFully(in, data);

        return data;
    }

    static S2K parseS2K(InputStream in)
        throws IOException
    {
        skipOpenParenthesis(in);

        String alg = readString(in, in.read());
        byte[] iv = readBytes(in, in.read());
        final long iterationCount = Long.parseLong(readString(in, in.read()));

        skipCloseParenthesis(in);

        // we have to return the actual iteration count provided.
        S2K s2k = new S2K(HashAlgorithmTags.SHA1, iv, (int)iterationCount)
        {
            public long getIterationCount()
            {
                return iterationCount;
            }
        };

        return s2k;
    }

    static void skipOpenParenthesis(InputStream in)
        throws IOException
    {
        int ch = in.read();
        if (ch != '(')
        {
            throw new IOException("unknown character encountered: " + (char)ch);
        }
    }

    static void skipCloseParenthesis(InputStream in)
        throws IOException
    {
        int ch = in.read();
        if (ch != ')')
        {
            throw new IOException("unknown character encountered");
        }
    }
}
