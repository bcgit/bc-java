package org.bouncycastle.tls.crypto;

public interface TlsECDomain
{
    TlsAgreement createECDH();

    TlsSignature createECDSA();
}
