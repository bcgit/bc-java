package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;

public interface TlsCrypto
{
    // TODO[tls-ops] We should review how feasible it is to not TlsContext within TlsCrypto
    void init(TlsContext context);

    TlsCertificate createCertificate(byte[] encoding) throws IOException;

    /**
     * See enumeration classes {@link EncryptionAlgorithm}, {@link MACAlgorithm} for appropriate argument values
     */
    TlsCipher createCipher(int encryptionAlgorithm, int macAlgorithm) throws IOException;

    TlsECDomain createECDomain(TlsECConfig ecConfig);

    TlsDHDomain createDHDomain(TlsDHConfig dhConfig);

    TlsSecret createSecret(byte[] data);

    TlsSecret generateRandomSecret(int length);

    TlsHash createHash(SignatureAndHashAlgorithm sidAlgorithm);

    TlsHash createHash(short algorithm);

    NonceRandomGenerator createNonceRandomGenerator();
}
