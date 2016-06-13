package org.bouncycastle.jsse.provider;

import java.util.Enumeration;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

class ProvSSLSessionContext
    implements SSLSessionContext
{
    public SSLSession getSession(byte[] bytes)
    {
        return null;
    }

    public Enumeration<byte[]> getIds()
    {
        return null;
    }

    public void setSessionTimeout(int i)
        throws IllegalArgumentException
    {

    }

    public int getSessionTimeout()
    {
        return 0;
    }

    public void setSessionCacheSize(int i)
        throws IllegalArgumentException
    {

    }

    public int getSessionCacheSize()
    {
        return 0;
    }
}
