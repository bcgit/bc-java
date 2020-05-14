package org.bouncycastle.jsse.provider.test;

interface CipherSuitesFilter
{
    boolean isIgnored(String cipherSuite);

    boolean isPermitted(String cipherSuite);
}
