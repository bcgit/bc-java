package org.bouncycastle.jsse.provider;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLKeyException;

import org.bouncycastle.jsse.BCExtendedSSLSession;

class ExportSSLSession_25
    extends ExportSSLSession_9
{
    ExportSSLSession_25(BCExtendedSSLSession sslSession)
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
