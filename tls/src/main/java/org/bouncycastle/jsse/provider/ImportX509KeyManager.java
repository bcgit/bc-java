package org.bouncycastle.jsse.provider;

import javax.net.ssl.X509KeyManager;

interface ImportX509KeyManager
{
    X509KeyManager unwrap();
}
