package org.bouncycastle.tls;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipherSuite;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsSRP6Client;
import org.bouncycastle.tls.crypto.TlsSRP6Server;
import org.bouncycastle.tls.crypto.TlsSRPConfig;
import org.bouncycastle.tls.crypto.TlsSecret;

// TODO[tls-ops] Move this back to tls.crypto package where it belongs

public interface TlsCrypto
{
    /**
     * Return the primary (safest) SecureRandom for this crypto.
     *
     * @return a SecureRandom suitable for key generation.
     */
    SecureRandom getSecureRandom();

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

    TlsHMAC createHMAC(int macAlgorithm)
        throws IOException;

    /**
     * Create a nonce byte[] string.
     *
     * @param size the length, in bytes, of the nonce to generate.
     * @return the nonce value.
     */
    byte[] createNonce(int size);

    /**
     * Create an SRP-6 client.
     *
     * @param srpConfig client config.
     * @return an initialised SRP6 client object,
     */
    TlsSRP6Client createSRP6Client(TlsSRPConfig srpConfig);

    /**
     * Create an SRP-6 server.
     *
     * @param srpConfig server config.
     * @param srpVerifier the SRP6 verifier value.
     * @return an initialised SRP6 server object.
     */
    TlsSRP6Server createSRP6Server(TlsSRPConfig srpConfig, BigInteger srpVerifier);
}
