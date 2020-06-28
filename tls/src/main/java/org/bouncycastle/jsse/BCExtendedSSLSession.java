package org.bouncycastle.jsse;

import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLSession;

public abstract class BCExtendedSSLSession implements SSLSession
{
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
}
