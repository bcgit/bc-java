package org.bouncycastle.jsse.provider;

import javax.net.ssl.X509TrustManager;

interface ImportX509TrustManager
{
    X509TrustManager unwrap();
}
