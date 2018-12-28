package org.bouncycastle.jsse.provider;

import java.lang.reflect.Method;
import java.util.List;

import javax.net.ssl.ExtendedSSLSession;

class ImportSSLSession_9
    extends ImportSSLSession_8
{
    private static final Method getStatusResponses = ReflectionUtil.getMethod("javax.net.ssl.ExtendedSSLSession",
        "getStatusResponses");

    ImportSSLSession_9(ExtendedSSLSession sslSession)
    {
        super(sslSession);
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<byte[]> getStatusResponses()
    {
        return (List<byte[]>)ReflectionUtil.invokeGetter(sslSession, getStatusResponses);
    }
}
