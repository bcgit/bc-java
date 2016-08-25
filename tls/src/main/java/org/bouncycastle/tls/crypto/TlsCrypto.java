package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsHash;

public interface TlsCrypto
{
    void init(TlsContext context);

    /**
     * See enumeration class {@link HashAlgorithm} for appropriate argument values
     */
    byte[] calculateDigest(short hashAlgorithm, byte[] buf, int off, int len) throws IOException;

    TlsCertificate createCertificate(byte[] encoding) throws IOException;

    /**
     * See enumeration classes {@link EncryptionAlgorithm}, {@link MACAlgorithm} for appropriate argument values
     */
    TlsCipher createCipher(int encryptionAlgorithm, int macAlgorithm) throws IOException;

    TlsECDomain createECDomain(TlsECConfig ecConfig);

    TlsDHDomain createDHDomain(TlsDHConfig dhConfig);

    TlsSecret createSecret(byte[] data);

    TlsSecret generateRandomSecret(int length);

    TlsHash createHash(SignatureAndHashAlgorithm algorithm);
}
