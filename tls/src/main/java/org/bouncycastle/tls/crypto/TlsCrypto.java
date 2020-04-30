package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;

/**
 * Service and object creation interface for the primitive types and services that are associated
 * with cryptography in the API.
 */
public interface TlsCrypto
{
    /**
     * Return true if this TlsCrypto can perform raw signatures and verifications for all supported algorithms.
     *
     * @return true if this instance can perform raw signatures and verifications for all supported algorithms, false otherwise.
     */
    boolean hasAllRawSignatureAlgorithms();

    /**
     * Return true if this TlsCrypto can support DH key agreement.
     *
     * @return true if this instance can support DH key agreement, false otherwise.
     */
    boolean hasDHAgreement();

    /**
     * Return true if this TlsCrypto can support ECDH key agreement.
     *
     * @return true if this instance can support ECDH key agreement, false otherwise.
     */
    boolean hasECDHAgreement();

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
     * Return true if this TlsCrypto supports the passed in {@link NamedGroup named group} value.
     *
     * @return true if this instance supports the passed in {@link NamedGroup named group} value.
     */
    boolean hasNamedGroup(int namedGroup);

    /**
     * Return true if this TlsCrypto can support RSA encryption/decryption.
     *
     * @return true if this instance can support RSA encryption/decryption, false otherwise.
     */
    boolean hasRSAEncryption();

    /**
     * Return true if this TlsCrypto can support the passed in signature algorithm
     * (not necessarily in combination with EVERY hash algorithm).
     *
     * @param signatureAlgorithm the algorithm of interest.
     * @return true if signatureAlgorithm is supported, false otherwise.
     */
    boolean hasSignatureAlgorithm(short signatureAlgorithm);

    /**
     * Return true if this TlsCrypto can support the passed in signature algorithm.
     *
     * @param sigAndHashAlgorithm the algorithm of interest.
     * @return true if sigAndHashAlgorithm is supported, false otherwise.
     */
    boolean hasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm);

    /**
     * Return true if this TlsCrypto can support the passed in signature scheme.
     *
     * @param signatureScheme the scheme of interest.
     * @return true if signatureScheme is supported, false otherwise.
     */
    boolean hasSignatureScheme(int signatureScheme);

    /**
     * Return true if this TlsCrypto can support SRP authentication.
     *
     * @return true if this instance can support SRP authentication, false otherwise.
     */
    boolean hasSRPAuthentication();

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
     * Create a cipher for the specified encryption and MAC algorithms.
     * <p>
     * See enumeration classes {@link EncryptionAlgorithm}, {@link MACAlgorithm} for appropriate argument values.
     * </p>
     * @param cryptoParams context specific parameters.
     * @param encryptionAlgorithm the encryption algorithm to be employed by the cipher.
     * @param macAlgorithm the MAC algorithm to be employed by the cipher.
     * @return a {@link TlsCipher} implementing the encryption and MAC algorithm.
     * @throws IOException
     */
    TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm)
        throws IOException;

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
     * Create a suitable hash for the hash algorithm identifier passed in.
     * <p>
     * See enumeration class {@link HashAlgorithm} for appropriate argument values.
     * </p>
     *
     * @param hashAlgorithm the hash algorithm the hash needs to implement.
     * @return a {@link TlsHash}.
     */
    TlsHash createHash(short hashAlgorithm);

    /**
     * Create a suitable HMAC using the hash algorithm identifier passed in.
     * <p>
     * See enumeration class {@link HashAlgorithm} for appropriate argument values.
     * </p>
     * @param hashAlgorithm the hash algorithm the HMAC should use.
     * @return a {@link TlsHMAC}.
     */
    TlsHMAC createHMAC(short hashAlgorithm);

    /**
     * Create a suitable HMAC for the MAC algorithm identifier passed in.
     * <p>
     * See enumeration class {@link MACAlgorithm} for appropriate argument values.
     * </p>
     * @param macAlgorithm the MAC algorithm the HMAC needs to match.
     * @return a {@link TlsHMAC}.
     */
    TlsHMAC createHMAC(int macAlgorithm);

    /**
     * Create a nonce generator. Each call should construct a new generator, and the generator
     * should be returned from this call only after automatically seeding from this
     * {@link TlsCrypto}'s entropy source, and from the provided additional seed material. The
     * output of each returned generator must be completely independent of the others.
     *
     * @param additionalSeedMaterial context-specific seed material
     * @return a {@link TlsNonceGenerator}
     */
    TlsNonceGenerator createNonceGenerator(byte[] additionalSeedMaterial);

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

    /**
     * Setup an initial "secret" for a chain of HKDF calls (RFC 5869), containing a string of HashLen zeroes.
     * 
     * @param hashAlgorithm the hash algorithm to instantiate HMAC with. See {@link HashAlgorithm} for values.
     */
    TlsSecret hkdfInit(short hashAlgorithm);
}
