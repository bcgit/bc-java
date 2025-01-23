package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.exception.OpenPGPKeyException;

public class OpenPGPKeyEditor
        extends AbstractOpenPGPKeySignatureGenerator
{

    private final OpenPGPImplementation implementation;
    private final OpenPGPPolicy policy;
    private OpenPGPKey key;

    public OpenPGPKeyEditor(OpenPGPKey key)
    {
        this(key, key.implementation);
    }

    public OpenPGPKeyEditor(OpenPGPKey key, OpenPGPImplementation implementation)
    {
        this(key, implementation, implementation.policy());
    }

    public OpenPGPKeyEditor(OpenPGPKey key, OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        this.key = key;
        this.implementation = implementation;
        this.policy = policy;
    }

    /**
     * Add a direct-key signature to the primary key.
     * The contents of the direct-key signature can be modified by providing a {@link SignatureParameters.Callback}.
     *
     * @param primaryKeyPassphrase passphrase of the primary key
     * @param callback callback to modify the direct-key signature contents
     * @return this
     * @throws PGPException if the key cannot be modified
     */
    public OpenPGPKeyEditor addDirectKeySignature(char[] primaryKeyPassphrase,
                                                  SignatureParameters.Callback callback)
            throws PGPException
    {
        SignatureParameters parameters = SignatureParameters.directKeySignature(policy);
        if (callback != null)
        {
            parameters = callback.apply(parameters);
        }

        if (parameters != null)
        {
            PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();
            PGPPrivateKey privatePrimaryKey = key.getPrimarySecretKey().unlock(primaryKeyPassphrase);

            PGPSignatureGenerator dkSigGen = new PGPSignatureGenerator(
                    implementation.pgpContentSignerBuilder(
                            publicPrimaryKey.getAlgorithm(),
                            parameters.getSignatureHashAlgorithmId()),
                    publicPrimaryKey);
            dkSigGen.init(parameters.getSignatureType(), privatePrimaryKey);

            // Hashed subpackets
            PGPSignatureSubpacketGenerator hashedSubpackets = new PGPSignatureSubpacketGenerator();
            hashedSubpackets.setIssuerFingerprint(true, publicPrimaryKey);
            hashedSubpackets.setSignatureCreationTime(parameters.getSignatureCreationTime());
            hashedSubpackets = parameters.applyToHashedSubpackets(hashedSubpackets);
            dkSigGen.setHashedSubpackets(hashedSubpackets.generate());

            // Unhashed subpackets
            PGPSignatureSubpacketGenerator unhashedSubpackets = new PGPSignatureSubpacketGenerator();
            unhashedSubpackets = parameters.applyToUnhashedSubpackets(unhashedSubpackets);
            dkSigGen.setUnhashedSubpackets(unhashedSubpackets.generate());

            // Inject signature into the certificate
            PGPSignature dkSig = dkSigGen.generateCertification(publicPrimaryKey);
            PGPPublicKey pubKey = PGPPublicKey.addCertification(publicPrimaryKey, dkSig);
            PGPPublicKeyRing publicKeyRing = PGPPublicKeyRing.insertPublicKey(key.getPGPPublicKeyRing(), pubKey);
            PGPSecretKeyRing secretKeyRing = PGPSecretKeyRing.replacePublicKeys(key.getPGPKeyRing(), publicKeyRing);

            this.key = new OpenPGPKey(secretKeyRing, implementation, policy);
        }
        return this;
    }

    /**
     * Add a user-id to the primary key.
     * If the key already contains the given user-id, a new certification signature will be added to the user-id.
     * @param userId user-id
     * @param primaryKeyPassphrase passphrase to unlock the primary key
     * @return this
     * @throws PGPException if the key cannot be modified
     */
    public OpenPGPKeyEditor addUserId(String userId, char[] primaryKeyPassphrase)
            throws PGPException
    {
        return addUserId(userId, primaryKeyPassphrase, null);
    }

    /**
     * Add a user-id to the primary key, modifying the contents of the certification signature using the given
     * {@link SignatureParameters.Callback}.
     * If the key already contains the given user-id, a new certification signature will be added to the user-id.
     *
     * @param userId user-id
     * @param primaryKeyPassphrase passphrase to unlock the primary key
     * @param callback callback to modify the certification signature contents
     * @return this
     * @throws PGPException if the key cannot be modified
     */
    public OpenPGPKeyEditor addUserId(String userId,
                                      char[] primaryKeyPassphrase,
                                      SignatureParameters.Callback callback)
            throws PGPException
    {
        if (userId == null || userId.trim().isEmpty())
        {
            throw new IllegalArgumentException("User-ID cannot be null or empty.");
        }

        SignatureParameters parameters = SignatureParameters.certification(policy);
        if (callback != null)
        {
            parameters = callback.apply(parameters);
        }

        if (parameters != null)
        {
            PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();
            PGPPrivateKey privatePrimaryKey = key.getPrimarySecretKey().unlock(primaryKeyPassphrase);

            PGPSignatureGenerator uidSigGen = new PGPSignatureGenerator(
                    implementation.pgpContentSignerBuilder(
                            publicPrimaryKey.getAlgorithm(),
                            parameters.getSignatureHashAlgorithmId()),
                    publicPrimaryKey);
            uidSigGen.init(parameters.getSignatureType(), privatePrimaryKey);

            // Hashed subpackets
            PGPSignatureSubpacketGenerator hashedSubpackets = new PGPSignatureSubpacketGenerator();
            hashedSubpackets.setIssuerFingerprint(true, publicPrimaryKey);
            hashedSubpackets.setSignatureCreationTime(parameters.getSignatureCreationTime());
            hashedSubpackets = parameters.applyToHashedSubpackets(hashedSubpackets);
            uidSigGen.setHashedSubpackets(hashedSubpackets.generate());

            // Unhashed subpackets
            PGPSignatureSubpacketGenerator unhashedSubpackets = new PGPSignatureSubpacketGenerator();
            unhashedSubpackets = parameters.applyToUnhashedSubpackets(unhashedSubpackets);
            uidSigGen.setUnhashedSubpackets(unhashedSubpackets.generate());

            // Inject UID and signature into the certificate
            PGPSignature uidSig = uidSigGen.generateCertification(userId, publicPrimaryKey);
            PGPPublicKey pubKey = PGPPublicKey.addCertification(publicPrimaryKey, userId, uidSig);
            PGPPublicKeyRing publicKeyRing = PGPPublicKeyRing.insertPublicKey(key.getPGPPublicKeyRing(), pubKey);
            PGPSecretKeyRing secretKeyRing = PGPSecretKeyRing.replacePublicKeys(key.getPGPKeyRing(), publicKeyRing);

            this.key = new OpenPGPKey(secretKeyRing, implementation, policy);
        }
        return this;
    }

    /**
     * Change the passphrase of the given component key.
     *
     * @param componentKey component key, whose passphrase shall be changed
     * @param oldPassphrase old passphrase (or null)
     * @param newPassphrase new passphrase (or null)
     * @param useAEAD whether to use AEAD
     * @return this
     * @throws OpenPGPKeyException if the secret component of the component key is missing
     * @throws PGPException if the key passphrase cannot be changed
     */
    public OpenPGPKeyEditor changePassphrase(OpenPGPCertificate.OpenPGPComponentKey componentKey,
                                             char[] oldPassphrase,
                                             char[] newPassphrase,
                                             boolean useAEAD)
            throws OpenPGPKeyException, PGPException
    {
        OpenPGPKey.OpenPGPSecretKey secretKey = key.getSecretKey(componentKey);
        if (secretKey == null)
        {
            throw new OpenPGPKeyException(componentKey, "Secret component key " + componentKey.getKeyIdentifier() +
                    " is missing from the key.");
        }

        PGPSecretKeyRing secretKeys = key.getPGPKeyRing();
        PGPSecretKey reencrypted = PGPSecretKey.copyWithNewPassword(
                secretKey.getPGPSecretKey(),
                implementation.pbeSecretKeyDecryptorBuilderProvider().provide().build(oldPassphrase),
                implementation.pbeSecretKeyEncryptorFactory(useAEAD)
                        .build(
                                newPassphrase,
                                secretKey.getPGPSecretKey().getPublicKey().getPublicKeyPacket()),
                implementation.pgpDigestCalculatorProvider().get(HashAlgorithmTags.SHA1));
        secretKeys = PGPSecretKeyRing.insertSecretKey(secretKeys, reencrypted);
        key = new OpenPGPKey(secretKeys, implementation, policy);

        return this;
    }

    /**
     * Return the modified {@link OpenPGPKey}.
     * @return modified key
     */
    public OpenPGPKey done()
    {
        return key;
    }

    /**
     * Revoke the given {@link OpenPGPCertificate.OpenPGPUserId}.
     *
     * @param userId user-id to be revoked
     * @param primaryKeyPassphrase passphrase of the primary key
     * @return this
     * @throws PGPException if the key cannot be modified
     */
    public OpenPGPKeyEditor revokeUserId(OpenPGPCertificate.OpenPGPUserId userId,
                                         char[] primaryKeyPassphrase)
            throws PGPException
    {
        return revokeUserId(userId, primaryKeyPassphrase, null);
    }


    /**
     * Revoke the given {@link OpenPGPCertificate.OpenPGPUserId}, allowing modification of the revocation signature
     * using the given {@link SignatureParameters.Callback}.
     *
     * @param userId user-id to revoke
     * @param primaryKeyPassphrase passphrase to unlock the primary key with
     * @param callback callback to modify the revocation signature contents
     * @return this
     * @throws PGPException if the key cannot be modified
     */
    public OpenPGPKeyEditor revokeUserId(OpenPGPCertificate.OpenPGPUserId userId,
                                         char[] primaryKeyPassphrase,
                                         SignatureParameters.Callback callback)
            throws PGPException
    {
        if (!key.getComponents().contains(userId))
        {
            throw new IllegalArgumentException("UserID is not part of the certificate.");
        }

        SignatureParameters parameters = SignatureParameters.certificationRevocation(policy);
        if (callback != null)
        {
            parameters = callback.apply(parameters);
        }

        if (parameters != null)
        {
            PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();
            PGPPrivateKey privatePrimaryKey = key.getPrimarySecretKey().unlock(primaryKeyPassphrase);

            PGPSignatureGenerator uidSigGen = new PGPSignatureGenerator(
                    implementation.pgpContentSignerBuilder(
                            publicPrimaryKey.getAlgorithm(),
                            parameters.getSignatureHashAlgorithmId()),
                    publicPrimaryKey);
            uidSigGen.init(parameters.getSignatureType(), privatePrimaryKey);

            // Hashed subpackets
            PGPSignatureSubpacketGenerator hashedSubpackets = new PGPSignatureSubpacketGenerator();
            hashedSubpackets.setIssuerFingerprint(true, publicPrimaryKey);
            hashedSubpackets.setSignatureCreationTime(parameters.getSignatureCreationTime());
            hashedSubpackets = parameters.applyToHashedSubpackets(hashedSubpackets);
            uidSigGen.setHashedSubpackets(hashedSubpackets.generate());

            // Unhashed subpackets
            PGPSignatureSubpacketGenerator unhashedSubpackets = new PGPSignatureSubpacketGenerator();
            unhashedSubpackets = parameters.applyToUnhashedSubpackets(unhashedSubpackets);
            uidSigGen.setUnhashedSubpackets(unhashedSubpackets.generate());

            // Inject signature into the certificate
            PGPSignature uidSig = uidSigGen.generateCertification(userId.getUserId(), publicPrimaryKey);
            PGPPublicKey pubKey = PGPPublicKey.addCertification(publicPrimaryKey, userId.getUserId(), uidSig);
            PGPPublicKeyRing publicKeyRing = PGPPublicKeyRing.insertPublicKey(key.getPGPPublicKeyRing(), pubKey);
            PGPSecretKeyRing secretKeyRing = PGPSecretKeyRing.replacePublicKeys(key.getPGPKeyRing(), publicKeyRing);

            this.key = new OpenPGPKey(secretKeyRing, implementation, policy);
        }
        return this;
    }
}
