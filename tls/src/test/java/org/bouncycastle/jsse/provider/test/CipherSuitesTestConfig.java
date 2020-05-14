package org.bouncycastle.jsse.provider.test;

import java.security.KeyStore;

public class CipherSuitesTestConfig
{
    public String category = null;
    public String cipherSuite = null;
    public KeyStore clientTrustStore = null;
    public boolean fips = false;
    public String protocol = null;
    public KeyStore serverKeyStore = null;
    public char[] serverPassword = null;
}
