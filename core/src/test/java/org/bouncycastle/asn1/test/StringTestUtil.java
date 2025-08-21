package org.bouncycastle.asn1.test;

import java.io.UnsupportedEncodingException;

import org.bouncycastle.util.Exceptions;

class StringTestUtil
{
    static byte[] toISO_8891(String str)
    {
        try
        {
            return str.getBytes("iso-8859-1");
        }
        catch (UnsupportedEncodingException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }

    static String fromISO_8891(byte[] encStr)
    {
        try
        {
            return new String(encStr, "iso-8859-1");
        }
        catch (UnsupportedEncodingException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }
}
