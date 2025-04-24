package org.bouncycastle.openpgp.api;

import java.io.InputStream;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilderProvider;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;

/**
 * Bouncy Castle provides two implementations of OpenPGP operators.
 * The <pre>JCA/JCE</pre> implementation makes use of Java Cryptography Architecture and the
 * Java Cryptography Extension, while <pre>Bc</pre> uses Bouncy Castles Lightweight Cryptography API.
 * The purpose of {@link OpenPGPImplementation} is to define a shared interface for instantiating concrete
 * objects of either API.
 * It is advised to define the desired implementation by calling {@link #setInstance(OpenPGPImplementation)} and
 * acquiring it via {@link #getInstance()}, as swapping out the entire implementation can then be done by
 * replacing the instance in one single place.
 * This pattern was successfully explored by PGPainless.
 */
public abstract class OpenPGPImplementation
{
    private static OpenPGPImplementation INSTANCE;
    private OpenPGPPolicy policy = new OpenPGPDefaultPolicy();

    /**
     * Replace the {@link OpenPGPImplementation} instance that is returned by {@link #getInstance()}.
     * @param implementation instance
     */
    public static void setInstance(OpenPGPImplementation implementation)
    {
        INSTANCE = implementation;
    }

    /**
     * Return the currently set {@link OpenPGPImplementation} instance.
     * The default is {@link BcOpenPGPImplementation}.
     *
     * @return instance
     */
    public static OpenPGPImplementation getInstance()
    {
        if (INSTANCE == null)
        {
            setInstance(new BcOpenPGPImplementation());
        }
        return INSTANCE;
    }

    public OpenPGPPolicy policy()
    {
        return policy;
    }

    public OpenPGPImplementation setPolicy(OpenPGPPolicy policy)
    {
        this.policy = policy;
        return this;
    }

    /**
     * Return an instance of {@link PGPObjectFactory} based on the given {@link InputStream}.
     *
     * @param packetInputStream packet input stream
     * @return object factory
     */
    public abstract PGPObjectFactory pgpObjectFactory(InputStream packetInputStream);

    /**
     * Return an instance of {@link PGPContentVerifierBuilderProvider} which is responsible for providing
     * implementations needed for signature verification.
     *
     * @return content verifier builder provider
     */
    public abstract PGPContentVerifierBuilderProvider pgpContentVerifierBuilderProvider();

    /**
     * Return an instance of {@link PBESecretKeyDecryptorBuilderProvider} which is responsible for providing
     * implementations needed for secret key unlocking.
     *
     * @return secret key decryptor builder provider
     */
    public abstract PBESecretKeyDecryptorBuilderProvider pbeSecretKeyDecryptorBuilderProvider();

    /**
     * Return an instance of {@link PGPDataEncryptorBuilder} which is responsible for providing implementations
     * needed for creating encrypted data packets.
     *
     * @param symmetricKeyAlgorithm symmetric encryption algorithm
     * @return data encryptor builder
     */
    public abstract PGPDataEncryptorBuilder pgpDataEncryptorBuilder(
            int symmetricKeyAlgorithm);

    /**
     * Return an instance of {@link PublicKeyKeyEncryptionMethodGenerator} which is responsible for
     * creating public-key-based encryptors for OpenPGP messages.
     * Public-key-based encryptors are used when a message is encrypted for a recipients public key.
     *
     * @param encryptionSubkey subkey for which a message shall be encrypted
     * @return public-key key-encryption method generator
     */
    public abstract PublicKeyKeyEncryptionMethodGenerator publicKeyKeyEncryptionMethodGenerator(
            PGPPublicKey encryptionSubkey);

    /**
     * Return an instance of {@link PBEKeyEncryptionMethodGenerator} which is responsible for creating
     * symmetric-key-based encryptors for OpenPGP messages, using {@link S2K#SALTED_AND_ITERATED} mode.
     * Symmetric-key-based encryptors are used when a message is encrypted using a passphrase.
     *
     * @param messagePassphrase passphrase to encrypt the message with
     * @return pbe key encryption method generator
     */
    public abstract PBEKeyEncryptionMethodGenerator pbeKeyEncryptionMethodGenerator(
            char[] messagePassphrase);

    /**
     * Return an instance of {@link PBEKeyEncryptionMethodGenerator} which is responsible for creating
     * symmetric-key-based encryptors for OpenPGP messages, using {@link S2K#ARGON_2} mode.
     * Symmetric-key-based encryptors are used when a message is encrypted using a passphrase.
     *
     * @param messagePassphrase passphrase to encrypt the message with
     * @param argon2Params parameters for the Argon2 hash function
     * @return pbe key encryption method generator
     */
    public abstract PBEKeyEncryptionMethodGenerator pbeKeyEncryptionMethodGenerator(
            char[] messagePassphrase,
            S2K.Argon2Params argon2Params);

    /**
     * Return an instance of {@link PGPContentSignerBuilder}, which is responsible for providing concrete
     * implementations needed for signature creation.
     *
     * @param publicKeyAlgorithm the signing-keys public-key algorithm
     * @param hashAlgorithm signature hash algorithm
     * @return content signer builder
     */
    public abstract PGPContentSignerBuilder pgpContentSignerBuilder(
            int publicKeyAlgorithm,
            int hashAlgorithm);

    /**
     * Return an instance of the {@link PBEDataDecryptorFactory}, which is responsible for providing concrete
     * implementations needed to decrypt OpenPGP messages that were encrypted symmetrically with a passphrase.
     *
     * @param messagePassphrase message passphrase
     * @return pbe data decryptor factory
     * @throws PGPException if the factory cannot be instantiated
     */
    public abstract PBEDataDecryptorFactory pbeDataDecryptorFactory(
            char[] messagePassphrase)
            throws PGPException;

    /**
     * Return an instance of the {@link SessionKeyDataDecryptorFactory}, which is responsible for providing
     * concrete implementations needed to decrypt OpenPGP messages using a {@link PGPSessionKey}.
     *
     * @param sessionKey session key
     * @return session-key data decryptor factory
     */
    public abstract SessionKeyDataDecryptorFactory sessionKeyDataDecryptorFactory(
            PGPSessionKey sessionKey);

    /**
     * Return an instance of the {@link PublicKeyDataDecryptorFactory}, which is responsible for providing
     * concrete implementations needed to decrypt OpenPGP messages using a {@link PGPPrivateKey}.
     *
     * @param decryptionKey private decryption key
     * @return public-key data decryptor factory
     */
    public abstract PublicKeyDataDecryptorFactory publicKeyDataDecryptorFactory(
            PGPPrivateKey decryptionKey);

    /**
     * Return an instance of the {@link PGPDigestCalculatorProvider}, which is responsible for providing
     * concrete {@link org.bouncycastle.openpgp.operator.PGPDigestCalculator} implementations.
     *
     * @return pgp digest calculator provider
     * @throws PGPException if the provider cannot be instantiated
     */
    public abstract PGPDigestCalculatorProvider pgpDigestCalculatorProvider()
            throws PGPException;

    public abstract PGPKeyPairGeneratorProvider pgpKeyPairGeneratorProvider();

    public abstract PGPContentSignerBuilderProvider pgpContentSignerBuilderProvider(int hashAlgorithmId);

    public abstract KeyFingerPrintCalculator keyFingerPrintCalculator();

    public abstract PBESecretKeyEncryptorFactory pbeSecretKeyEncryptorFactory(boolean aead) throws PGPException;

    public abstract PBESecretKeyEncryptorFactory pbeSecretKeyEncryptorFactory(boolean aead, int symmetricKeyAlgorithm, int iterationCount) throws PGPException;
}
