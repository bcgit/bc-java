package org.bouncycastle.jsse.provider;

import javax.crypto.SecretKey;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLKeyException;

class ImportSSLSession_25
    extends ImportSSLSession_9
{
    ImportSSLSession_25(ExtendedSSLSession sslSession)
    {
        super(sslSession);
    }

    @Override
    public byte[] exportKeyingMaterialData(String label, byte[] context, int length) throws SSLKeyException
    {
        return sslSession.exportKeyingMaterialData(label, context, length);
    }

    @Override
    public SecretKey exportKeyingMaterialKey(String keyAlg, String label, byte[] context, int length)
        throws SSLKeyException
    {
        return sslSession.exportKeyingMaterialKey(keyAlg, label, context, length);
    }
}
