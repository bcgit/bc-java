package org.bouncycastle.openpgp.api;

import java.util.Date;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPException;

/**
 * Main entry to the high level OpenPGP API.
 */
public abstract class OpenPGPApi
{
    private final OpenPGPImplementation implementation;
    private final OpenPGPPolicy policy;

    /**
     * Instantiate an {@link OpenPGPApi} based on the given {@link OpenPGPImplementation}.
     *
     * @param implementation OpenPGP implementation
     */
    public OpenPGPApi(OpenPGPImplementation implementation)
    {
        this(implementation, implementation.policy());
    }

    /**
     * Instantiate an {@link OpenPGPApi} object, passing in an {@link OpenPGPImplementation} and custom
     * {@link OpenPGPPolicy}.
     *
     * @param implementation OpenPGP implementation
     * @param policy algorithm policy
     */
    public OpenPGPApi(OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        this.implementation = implementation;
        this.policy = policy;
    }

    /**
     * Return an {@link OpenPGPKeyReader} which can be used to parse binary or ASCII armored
     * {@link OpenPGPKey OpenPGPKeys} or {@link OpenPGPCertificate OpenPGPCertificates}.
     *
     * @return key reader
     */
    public OpenPGPKeyReader readKeyOrCertificate()
    {
        return new OpenPGPKeyReader(implementation, policy);
    }

    /**
     * Return an {@link OpenPGPKeyGenerator} which can be used to generate {@link OpenPGPKey OpenPGPKeys}.
     * This method returns a generator for OpenPGP v6 keys as defined by rfc9580.
     *
     * @return key generator
     * @throws PGPException if the key generator cannot be set up
     */
    public OpenPGPKeyGenerator generateKey()
            throws PGPException
    {
        return generateKey(PublicKeyPacket.VERSION_6);
    }

    /**
     * Return an {@link OpenPGPKeyGenerator} which can be used to generate {@link OpenPGPKey OpenPGPKeys}
     * of the given key version.
     * Valid version numbers are:
     * <ul>
     *     <li>{@link PublicKeyPacket#VERSION_4} (rfc4880)</li>
     *     <li>{@link PublicKeyPacket#VERSION_6} (rfc9580)</li>
     *     <li>{@link PublicKeyPacket#LIBREPGP_5} (LibrePGP; experimental)</li>
     * </ul>
     *
     * @param version key version number
     * @return key generator
     * @throws PGPException if the key generator cannot be set up
     */
    public abstract OpenPGPKeyGenerator generateKey(int version)
            throws PGPException;

    /**
     * Return an {@link OpenPGPKeyGenerator} which can be used to generate {@link OpenPGPKey OpenPGPKeys}.
     * The key and signatures will have a creation time of the passed creationTime.
     * This method returns a generator for OpenPGP v6 keys as defined by rfc9580.
     *
     * @param creationTime key + signature creation time
     * @return key generator
     * @throws PGPException if the key generator cannot be set up
     */
    public OpenPGPKeyGenerator generateKey(Date creationTime)
            throws PGPException
    {
        return generateKey(PublicKeyPacket.VERSION_6, creationTime);
    }

    /**
     * Return an {@link OpenPGPKeyGenerator} which can be used to generate {@link OpenPGPKey OpenPGPKeys}
     * of the given key version.
     * The key and signatures will have a creation time of the passed creationTime.
     * Valid version numbers are:
     * <ul>
     *     <li>{@link PublicKeyPacket#VERSION_4} (rfc4880)</li>
     *     <li>{@link PublicKeyPacket#VERSION_6} (rfc9580)</li>
     *     <li>{@link PublicKeyPacket#LIBREPGP_5} (LibrePGP; experimental)</li>
     * </ul>
     *
     * @param version key version number
     * @param creationTime key + signatures creation time
     * @return key generator
     * @throws PGPException if the key generator cannot be set up
     */
    public abstract OpenPGPKeyGenerator generateKey(int version,
                                                    Date creationTime)
            throws PGPException;

    /**
     * Return an {@link OpenPGPKeyGenerator} which can be used to generate {@link OpenPGPKey OpenPGPKeys}.
     * The key and signatures will have a creation time of the passed creationTime.
     * If aeadProtection is true, the key will use AEAD+Argon2 to protect the secret key material,
     * otherwise it will use salted+iterated CFB mode.
     * This method returns a generator for OpenPGP v6 keys as defined by rfc9580.
     *
     * @param creationTime key + signature creation time
     * @param aeadProtection whether to use AEAD or CFB protection
     * @return key generator
     * @throws PGPException if the key generator cannot be set up
     */
    public OpenPGPKeyGenerator generateKey(Date creationTime, boolean aeadProtection)
            throws PGPException
    {
        return generateKey(PublicKeyPacket.VERSION_6, creationTime, aeadProtection);
    }

    /**
     * Return an {@link OpenPGPKeyGenerator} which can be used to generate {@link OpenPGPKey OpenPGPKeys}
     * of the given key version.
     * The key and signatures will have a creation time of the passed creationTime.
     * If aeadProtection is true, the key will use AEAD+Argon2 to protect the secret key material,
     * otherwise it will use salted+iterated CFB mode.
     * Valid version numbers are:
     * <ul>
     *     <li>{@link PublicKeyPacket#VERSION_4} (rfc4880)</li>
     *     <li>{@link PublicKeyPacket#VERSION_6} (rfc9580)</li>
     *     <li>{@link PublicKeyPacket#LIBREPGP_5} (LibrePGP; experimental)</li>
     * </ul>
     *
     * @param creationTime key + signature creation time
     * @param aeadProtection whether to use AEAD or CFB protection
     * @return key generator
     * @throws PGPException if the key generator cannot be set up
     */
    public abstract OpenPGPKeyGenerator generateKey(int version,
                                                    Date creationTime,
                                                    boolean aeadProtection)
            throws PGPException;

    /**
     * Create an inline-signed and/or encrypted OpenPGP message.
     *
     * @return message generator
     */
    public OpenPGPMessageGenerator signAndOrEncryptMessage()
    {
        return new OpenPGPMessageGenerator(implementation, policy);
    }

    /**
     * Create one or more detached signatures over some data.
     *
     * @return signature generator
     */
    public OpenPGPDetachedSignatureGenerator createDetachedSignature()
    {
        return new OpenPGPDetachedSignatureGenerator(implementation, policy);
    }

    /**
     * Decrypt and/or verify an OpenPGP message.
     *
     * @return message processor
     */
    public OpenPGPMessageProcessor decryptAndOrVerifyMessage()
    {
        return new OpenPGPMessageProcessor(implementation, policy);
    }

    /**
     * Verify detached signatures over some data.
     *
     * @return signature processor
     */
    public OpenPGPDetachedSignatureProcessor verifyDetachedSignature()
    {
        return new OpenPGPDetachedSignatureProcessor(implementation, policy);
    }

    public OpenPGPKeyEditor editKey(OpenPGPKey key)
            throws PGPException
    {
        return editKey(key, (char[]) null);
    }

    public OpenPGPKeyEditor editKey(OpenPGPKey key, final char[] primaryKeyPassphrase)
            throws PGPException
    {
        return new OpenPGPKeyEditor(
                key,
                new KeyPassphraseProvider()
                {
                    @Override
                    public char[] getKeyPassword(OpenPGPKey.OpenPGPSecretKey key)
                    {
                        return primaryKeyPassphrase;
                    }
                },
                implementation,
                policy);
    }

    /**
     * Modify an {@link OpenPGPKey}.
     *
     * @param key OpenPGP key
     * @return key editor
     */
    public OpenPGPKeyEditor editKey(OpenPGPKey key, KeyPassphraseProvider primaryKeyPassphraseProvider)
            throws PGPException
    {
        return new OpenPGPKeyEditor(key, primaryKeyPassphraseProvider, implementation, policy);
    }

    /**
     * Return the underlying {@link OpenPGPImplementation} of this API handle.
     *
     * @return OpenPGP implementation
     */
    public OpenPGPImplementation getImplementation()
    {
        return implementation;
    }
}
