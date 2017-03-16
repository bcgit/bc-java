package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Set;

import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;

/**
 * Service and object creation interface for the primitive types and services that are associated
 * with cryptography in the API.
 */
public interface TlsCrypto
{
    /**
     * Return the set of supported curves that can be used with this TlsCrypto.
     *
     * @return a set of curve IDs.
     */
    Set<Integer> getSupportedNamedCurves();

    /**
     * Return true if this TlsCrypto can perform raw signatures and verifications for all supported algorithms.
     *
     * @return true if this instance can perform raw signatures and verifications for all supported algorithms, false otherwise.
     */
    boolean hasAllRawSignatureAlgorithms();

    /**
     * Return true if this TlsCrypto can support the passed in block/stream encryption algorithm.
     *
     * @param encryptionAlgorithm the algorithm of interest.
     * @return true if encryptionAlgorithm is supported, false otherwise.
     */
    boolean hasEncryptionAlgorithm(int encryptionAlgorithm);

    /**
     * Return true if this TlsCrypto can support the passed in hash algorithm.
     *
     * @param hashAlgorithm the algorithm of interest.
     * @return true if hashAlgorithm is supported, false otherwise.
     */
    boolean hasHashAlgorithm(short hashAlgorithm);

    /**
     * Return true if this TlsCrypto can support the passed in MAC algorithm.
     *
     * @param macAlgorithm the algorithm of interest.
     * @return true if macAlgorithm is supported, false otherwise.
     */
    boolean hasMacAlgorithm(int macAlgorithm);

    /**
     * Return true if this TlsCrypto can support the passed in signature algorithm.
     *
     * @param sigAndHashAlgorithm the algorithm of interest.
     * @return true if sigAndHashAlgorithm is supported, false otherwise.
     */
    boolean hasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm);

    /**
     * Return true if this TlsCrypto can support RSA encryption/decryption.
     *
     * @return true if this instance can support RSA encryption/decryption, false otherwise.
     */
    boolean hasRSAEncryption();

    /**
     * Create a TlsSecret object based provided data.
     *
     * @param data the data to base the TlsSecret on.
     * @return a TlsSecret based on random data.
     */
    TlsSecret createSecret(byte[] data);

    /**
     * Create a TlsSecret object containing a randomly-generated RSA PreMasterSecret
     *
     * @param clientVersion the client version to place in the first 2 bytes
     * @return a TlsSecret containing the PreMasterSecret.
     */
    TlsSecret generateRSAPreMasterSecret(ProtocolVersion clientVersion);

    /**
     * Return the primary (safest) SecureRandom for this crypto.
     *
     * @return a SecureRandom suitable for key generation.
     */
    SecureRandom getSecureRandom();

    /**
     * Create a TlsCertificate from a ASN.1 binary encoding of an X.509 certificate.
     *
     * @param encoding DER/BER encoding of the certificate of interest.
     * @return a TlsCertificate.
     *
     * @throws IOException if there is an issue on decoding or constructing the certificate.
     */
    TlsCertificate createCertificate(byte[] encoding) throws IOException;

    /**
     * Create an domain object supporting the domain parameters described in dhConfig.
     *
     * @param dhConfig the config describing the DH parameters to use.
     * @return a TlsECDomain supporting the parameters in ecConfig.
     */
    TlsDHDomain createDHDomain(TlsDHConfig dhConfig);

    /**
     * Create an domain object supporting the domain parameters described in ecConfig.
     *
     * @param ecConfig the config describing the EC parameters to use.
     * @return a TlsECDomain supporting the parameters in ecConfig.
     */
    TlsECDomain createECDomain(TlsECConfig ecConfig);

    /**
     * Adopt the passed in secret, creating a new copy of it..
     *
     * @param secret the secret to make a copy of.
     * @return a TlsSecret based the original secret.
     */
    TlsSecret adoptSecret(TlsSecret secret);

    /**
     * Create a suitable hash for the signature algorithm identifier passed in.
     *
     * @param sidAlgorithm the signature algorithm the hash needs to match.
     * @return a TlsHash.
     */
    TlsHash createHash(SignatureAndHashAlgorithm sidAlgorithm);

    /**
     * Create a suitable hash for the hash algorithm identifier passed in.
     *
     * @param algorithm the hash algorithm the hash needs to implement.
     * @return a TlsHash.
     */
    TlsHash createHash(short algorithm);

    /**
     * Create a suitable HMAC for the MAC algorithm identifier passed in.
     * <p>
     * See enumeration class {@link MACAlgorithm} for appropriate argument values.
     * </p>
     * @param macAlgorithm the MAC algorithm the HMAC needs to match.
     * @return a TlsHMAC.
     */
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

    /**
     * Create an SRP-6 verifier generator.
     *
     * @param srpConfig generator config.
     * @return an initialized SRP6 verifier generator,
     */
    TlsSRP6VerifierGenerator createSRP6VerifierGenerator(TlsSRPConfig srpConfig);
}
