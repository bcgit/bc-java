package org.bouncycastle.jsse.provider;

import java.util.List;

import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCSNIServerName;

interface ProvSSLSession
    extends SSLSession
{
    String[] getLocalSupportedSignatureAlgorithms();

    String[] getPeerSupportedSignatureAlgorithms();

    List<BCSNIServerName> getRequestedServerNames();
}
