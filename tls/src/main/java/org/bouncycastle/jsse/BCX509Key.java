package org.bouncycastle.jsse;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface BCX509Key
{
    X509Certificate[] getCertificateChain();

    PrivateKey getPrivateKey();
}
