package org.bouncycastle.tls;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipherSuite;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsSecret;

public interface TlsCrypto
{
    TlsCertificate createCertificate(byte[] encoding) throws IOException;

    /**
     * See enumeration classes {@link EncryptionAlgorithm}, {@link MACAlgorithm} for appropriate argument values
     */
    TlsCipherSuite createCipher(int encryptionAlgorithm, int macAlgorithm) throws IOException;

    TlsECDomain createECDomain(TlsECConfig ecConfig);

    TlsDHDomain createDHDomain(TlsDHConfig dhConfig);

    TlsSecret createSecret(byte[] data);

    TlsSecret generateRandomSecret(int length);

    TlsHash createHash(SignatureAndHashAlgorithm sidAlgorithm);

    TlsHash createHash(short algorithm);

    byte[] createNonce(int size);

    SecureRandom getSecureRandom();
}
