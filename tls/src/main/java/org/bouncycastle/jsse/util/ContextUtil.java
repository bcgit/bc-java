package org.bouncycastle.jsse.util;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;

import org.bouncycastle.jsse.BCSSLContext;
import org.bouncycastle.jsse.BCSSLSessionContext;

public class ContextUtil
{
    /**
     * Returns a {@link BCSSLContext} describing the current initialization of an {@link SSLContext}.
     *
     * @param sslContext
     *            the {@link SSLContext}
     * @return a {@link BCSSLContext} for the current initialization of the SSLContext, or
     *         <code>null</code> if the SSLContext is not from the BCJSSE provider
     * @throws IllegalStateException
     *             if the SSLContext has not been initialized
     */
    public static BCSSLContext getBCSSLContext(SSLContext sslContext)
    {
        SSLSessionContext sessionContext = sslContext.getClientSessionContext();
        if (sessionContext instanceof BCSSLSessionContext)
        {
            return ((BCSSLSessionContext)sessionContext).getBCSSLContext();
        }
        return null;
    }
}
