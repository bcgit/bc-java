package org.bouncycastle.jsse;

import java.util.Collections;
import java.util.List;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLKeyException;
import javax.net.ssl.SSLSession;

public abstract class BCExtendedSSLSession implements SSLSession
{
    public byte[] exportKeyingMaterialData(String label, byte[] context, int length) throws SSLKeyException
    {
        throw new UnsupportedOperationException();
    }

    public SecretKey exportKeyingMaterialKey(String keyAlg, String label, byte[] context, int length)
        throws SSLKeyException
    {
        throw new UnsupportedOperationException();
    }

    public abstract String[] getLocalSupportedSignatureAlgorithms();

    public String[] getLocalSupportedSignatureAlgorithmsBC()
    {
        return getLocalSupportedSignatureAlgorithms();
    }

    public abstract String[] getPeerSupportedSignatureAlgorithms();

    public String[] getPeerSupportedSignatureAlgorithmsBC()
    {
        return getPeerSupportedSignatureAlgorithms();
    }

    public List<BCSNIServerName> getRequestedServerNames()
    {
        throw new UnsupportedOperationException();
    }

    public List<byte[]> getStatusResponses()
    {
        return Collections.emptyList();
    }

    public abstract boolean isFipsMode();
}
