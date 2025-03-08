package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyValidationException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.exception.OpenPGPKeyException;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;

import java.io.IOException;
import java.util.Date;

public class OpenPGPKeyEditor
        extends AbstractOpenPGPKeySignatureGenerator
{

    private final OpenPGPImplementation implementation;
    private final OpenPGPPolicy policy;
    private OpenPGPKey key;
    private final OpenPGPKey.OpenPGPPrivateKey primaryKey;

    public OpenPGPKeyEditor(OpenPGPKey key, KeyPassphraseProvider passphraseProvider)
            throws PGPException
    {
        this(key, passphraseProvider, key.implementation);
    }

    public OpenPGPKeyEditor(OpenPGPKey key,
                            KeyPassphraseProvider passphraseProvider,
                            OpenPGPImplementation implementation)
            throws PGPException
    {
        this(key, passphraseProvider, implementation, implementation.policy());
    }

    public OpenPGPKeyEditor(OpenPGPKey key,
                            KeyPassphraseProvider passphraseProvider,
                            OpenPGPImplementation implementation,
                            OpenPGPPolicy policy)
            throws PGPException
    {
        this.key = key;
        this.primaryKey = key.getPrimarySecretKey().unlock(passphraseProvider);
        this.implementation = implementation;
        this.policy = policy;
    }

    public OpenPGPKeyEditor addDirectKeySignature(SignatureParameters.Callback signatureCallback)
            throws PGPException
    {
        SignatureParameters parameters = SignatureParameters.directKeySignature(policy);
        if (signatureCallback != null)
        {
            parameters = signatureCallback.apply(parameters);
        }

        if (parameters != null)
        {
            PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();

            PGPSignatureGenerator dkSigGen = new PGPSignatureGenerator(
                    implementation.pgpContentSignerBuilder(
                            publicPrimaryKey.getAlgorithm(),
                            parameters.getSignatureHashAlgorithmId()),
                    publicPrimaryKey);
            dkSigGen.init(parameters.getSignatureType(), primaryKey.getKeyPair().getPrivateKey());

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
     *
     *  @param userId user-id
     * @return this
     * @throws PGPException if the key cannot be modified
     */
    public OpenPGPKeyEditor addUserId(String userId)
            throws PGPException
    {
        return addUserId(userId, null);
    }

    /**
     * Add a user-id to the primary key, modifying the contents of the certification signature using the given
     * {@link SignatureParameters.Callback}.
     * If the key already contains the given user-id, a new certification signature will be added to the user-id.
     *
     * @param userId user-id
     * @param signatureCallback callback to modify the certification signature contents
     * @return this
     * @throws PGPException if the key cannot be modified
     */
    public OpenPGPKeyEditor addUserId(String userId,
                                      SignatureParameters.Callback signatureCallback)
            throws PGPException
    {
        if (userId == null || userId.trim().isEmpty())
        {
            throw new IllegalArgumentException("User-ID cannot be null or empty.");
        }

        SignatureParameters parameters = SignatureParameters.certification(policy);
        if (signatureCallback != null)
        {
            parameters = signatureCallback.apply(parameters);
        }

        if (parameters != null)
        {
            PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();

            PGPSignatureGenerator uidSigGen = new PGPSignatureGenerator(
                    implementation.pgpContentSignerBuilder(
                            publicPrimaryKey.getAlgorithm(),
                            parameters.getSignatureHashAlgorithmId()),
                    publicPrimaryKey);
            uidSigGen.init(parameters.getSignatureType(), primaryKey.getKeyPair().getPrivateKey());

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
     * Revoke the given {@link OpenPGPCertificate.OpenPGPIdentityComponent}.
     *
     * @param identity user-id to be revoked
     * @return this
     * @throws PGPException if the key cannot be modified
     */
    public OpenPGPKeyEditor revokeIdentity(OpenPGPCertificate.OpenPGPIdentityComponent identity)
            throws PGPException
    {
        return revokeIdentity(identity, null);
    }

    /**
     * Revoke the given {@link OpenPGPCertificate.OpenPGPUserId}, allowing modification of the revocation signature
     * using the given {@link SignatureParameters.Callback}.
     *
     * @param identity user-id to revoke
     * @param signatureCallback callback to modify the revocation signature contents
     * @return this
     * @throws PGPException if the key cannot be modified
     */
    public OpenPGPKeyEditor revokeIdentity(OpenPGPCertificate.OpenPGPIdentityComponent identity,
                                           SignatureParameters.Callback signatureCallback)
            throws PGPException
    {
        if (!key.getComponents().contains(identity))
        {
            throw new IllegalArgumentException("UserID or UserAttribute is not part of the certificate.");
        }

        SignatureParameters parameters = SignatureParameters.certificationRevocation(policy);
        if (signatureCallback != null)
        {
            parameters = signatureCallback.apply(parameters);
        }

        if (parameters != null)
        {
            PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();

            PGPSignatureGenerator idSigGen = new PGPSignatureGenerator(
                    implementation.pgpContentSignerBuilder(
                            publicPrimaryKey.getAlgorithm(),
                            parameters.getSignatureHashAlgorithmId()),
                    publicPrimaryKey);
            idSigGen.init(parameters.getSignatureType(), primaryKey.getKeyPair().getPrivateKey());

            // Hashed subpackets
            PGPSignatureSubpacketGenerator hashedSubpackets = new PGPSignatureSubpacketGenerator();
            hashedSubpackets.setIssuerFingerprint(true, publicPrimaryKey);
            hashedSubpackets.setSignatureCreationTime(parameters.getSignatureCreationTime());
            hashedSubpackets = parameters.applyToHashedSubpackets(hashedSubpackets);
            idSigGen.setHashedSubpackets(hashedSubpackets.generate());

            // Unhashed subpackets
            PGPSignatureSubpacketGenerator unhashedSubpackets = new PGPSignatureSubpacketGenerator();
            unhashedSubpackets = parameters.applyToUnhashedSubpackets(unhashedSubpackets);
            idSigGen.setUnhashedSubpackets(unhashedSubpackets.generate());

            // Inject signature into the certificate
            PGPPublicKey pubKey;
            if (identity instanceof OpenPGPCertificate.OpenPGPUserId)
            {
                OpenPGPCertificate.OpenPGPUserId userId = (OpenPGPCertificate.OpenPGPUserId) identity;
                PGPSignature uidSig = idSigGen.generateCertification(userId.getUserId(), publicPrimaryKey);
                pubKey = PGPPublicKey.addCertification(publicPrimaryKey, userId.getUserId(), uidSig);
            }
            else
            {
                OpenPGPCertificate.OpenPGPUserAttribute userAttribute = (OpenPGPCertificate.OpenPGPUserAttribute) identity;
                PGPSignature uattrSig = idSigGen.generateCertification(userAttribute.getUserAttribute(), publicPrimaryKey);
                pubKey = PGPPublicKey.addCertification(publicPrimaryKey, userAttribute.getUserAttribute(), uattrSig);
            }
            PGPPublicKeyRing publicKeyRing = PGPPublicKeyRing.insertPublicKey(key.getPGPPublicKeyRing(), pubKey);
            PGPSecretKeyRing secretKeyRing = PGPSecretKeyRing.replacePublicKeys(key.getPGPKeyRing(), publicKeyRing);

            this.key = new OpenPGPKey(secretKeyRing, implementation, policy);
        }
        return this;
    }

    public OpenPGPKeyEditor addEncryptionSubkey()
            throws PGPException
    {
        return addEncryptionSubkey(KeyPairGeneratorCallback.encryptionKey());
    }

    public OpenPGPKeyEditor addEncryptionSubkey(KeyPairGeneratorCallback keyGenCallback)
            throws PGPException
    {
        return addEncryptionSubkey(keyGenCallback, key.getPrimaryKey().getVersion(), new Date());
    }

    public OpenPGPKeyEditor addEncryptionSubkey(KeyPairGeneratorCallback keyGenCallback,
                                                int version,
                                                Date creationTime)
            throws PGPException
    {
        PGPKeyPairGenerator kpGen = implementation.pgpKeyPairGeneratorProvider()
                .get(version, creationTime);
        return addEncryptionSubkey(keyGenCallback.generateFrom(kpGen), null);
    }

    public OpenPGPKeyEditor addEncryptionSubkey(PGPKeyPair encryptionSubkey,
                                                SignatureParameters.Callback bindingSigCallback)
            throws PGPException
    {
        if (!PublicKeyUtils.isEncryptionAlgorithm(encryptionSubkey.getPublicKey().getAlgorithm()))
        {
            throw new PGPKeyValidationException("Provided subkey is not encryption-capable.");
        }

        SignatureParameters parameters = SignatureParameters.subkeyBinding(policy);

        if (bindingSigCallback != null)
        {
            parameters = bindingSigCallback.apply(parameters);
        }

        if (parameters != null)
        {
            PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();

            PGPSignatureGenerator subKeySigGen = new PGPSignatureGenerator(
                    implementation.pgpContentSignerBuilder(
                            publicPrimaryKey.getAlgorithm(),
                            parameters.getSignatureHashAlgorithmId()),
                    publicPrimaryKey);
            subKeySigGen.init(parameters.getSignatureType(), primaryKey.getKeyPair().getPrivateKey());

            // Hashed subpackets
            PGPSignatureSubpacketGenerator hashedSubpackets = new PGPSignatureSubpacketGenerator();
            hashedSubpackets.setIssuerFingerprint(true, publicPrimaryKey);
            hashedSubpackets.setSignatureCreationTime(parameters.getSignatureCreationTime());
            hashedSubpackets.setKeyFlags(KeyFlags.ENCRYPT_STORAGE | KeyFlags.ENCRYPT_COMMS);
            hashedSubpackets = parameters.applyToHashedSubpackets(hashedSubpackets);
            subKeySigGen.setHashedSubpackets(hashedSubpackets.generate());

            // Unhashed subpackets
            PGPSignatureSubpacketGenerator unhashedSubpackets = new PGPSignatureSubpacketGenerator();
            unhashedSubpackets = parameters.applyToUnhashedSubpackets(unhashedSubpackets);
            subKeySigGen.setUnhashedSubpackets(unhashedSubpackets.generate());

            // Inject signature into the certificate
            PGPPublicKey publicSubKey = encryptionSubkey.getPublicKey();
            PGPSignature subKeySig = subKeySigGen.generateCertification(publicPrimaryKey, publicSubKey);
            publicSubKey = PGPPublicKey.addCertification(publicSubKey, subKeySig);
            PGPSecretKey secretSubkey = new PGPSecretKey(
                    encryptionSubkey.getPrivateKey(),
                    publicSubKey,
                    implementation.pgpDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                    false,
                    null);
            PGPSecretKeyRing secretKeyRing = PGPSecretKeyRing.insertSecretKey(key.getPGPKeyRing(), secretSubkey);

            this.key = new OpenPGPKey(secretKeyRing, implementation, policy);
        }
        return this;
    }

    public OpenPGPKeyEditor addSigningSubkey()
            throws PGPException
    {
        return addSigningSubkey(KeyPairGeneratorCallback.signingKey());
    }

    public OpenPGPKeyEditor addSigningSubkey(KeyPairGeneratorCallback keyGenCallback)
            throws PGPException
    {
        return addSigningSubkey(keyGenCallback, key.getPrimaryKey().getVersion(), new Date());
    }

    public OpenPGPKeyEditor addSigningSubkey(KeyPairGeneratorCallback keyGenCallback,
                                             int version,
                                             Date creationTime)
            throws PGPException
    {
        PGPKeyPairGenerator kpGen = implementation.pgpKeyPairGeneratorProvider()
                .get(version, creationTime);
        return addSigningSubkey(keyGenCallback.generateFrom(kpGen), null, null);
    }

    public OpenPGPKeyEditor addSigningSubkey(PGPKeyPair signingSubkey,
                                             SignatureParameters.Callback bindingSigCallback,
                                             SignatureParameters.Callback backSigCallback)
            throws PGPException
    {
        if (!PublicKeyUtils.isSigningAlgorithm(signingSubkey.getPublicKey().getAlgorithm()))
        {
            throw new PGPKeyValidationException("Provided subkey is not signing-capable.");
        }

        SignatureParameters backSigParameters = SignatureParameters.primaryKeyBinding(policy);
        if (backSigCallback != null)
        {
            backSigParameters = backSigCallback.apply(backSigParameters);
        }

        PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();

        PGPSignature backSig = null;
        if (backSigParameters != null)
        {
            PGPSignatureGenerator backSigGen = new PGPSignatureGenerator(
                    implementation.pgpContentSignerBuilder(signingSubkey.getPublicKey().getAlgorithm(),
                            backSigParameters.getSignatureHashAlgorithmId()),
                    signingSubkey.getPublicKey());
            backSigGen.init(backSigParameters.getSignatureType(), signingSubkey.getPrivateKey());

            PGPSignatureSubpacketGenerator hashedSubpackets = new PGPSignatureSubpacketGenerator();
            hashedSubpackets.setIssuerFingerprint(true, signingSubkey.getPublicKey());
            hashedSubpackets = backSigParameters.applyToHashedSubpackets(hashedSubpackets);
            backSigGen.setHashedSubpackets(hashedSubpackets.generate());

            PGPSignatureSubpacketGenerator unhashedSubpackets = new PGPSignatureSubpacketGenerator();
            unhashedSubpackets = backSigParameters.applyToUnhashedSubpackets(unhashedSubpackets);
            backSigGen.setUnhashedSubpackets(unhashedSubpackets.generate());

            backSig = backSigGen.generateCertification(publicPrimaryKey, signingSubkey.getPublicKey());
        }

        SignatureParameters parameters = SignatureParameters.subkeyBinding(policy);
        if (bindingSigCallback != null)
        {
            parameters = bindingSigCallback.apply(parameters);
        }

        if (parameters != null)
        {
            PGPSignatureGenerator subKeySigGen = new PGPSignatureGenerator(
                    implementation.pgpContentSignerBuilder(
                            publicPrimaryKey.getAlgorithm(),
                            parameters.getSignatureHashAlgorithmId()),
                    publicPrimaryKey);
            subKeySigGen.init(parameters.getSignatureType(), primaryKey.getKeyPair().getPrivateKey());

            // Hashed subpackets
            PGPSignatureSubpacketGenerator hashedSubpackets = new PGPSignatureSubpacketGenerator();
            hashedSubpackets.setIssuerFingerprint(true, publicPrimaryKey);
            hashedSubpackets.setSignatureCreationTime(parameters.getSignatureCreationTime());
            hashedSubpackets.setKeyFlags(KeyFlags.SIGN_DATA);
            if (backSig != null)
            {
                try
                {
                    hashedSubpackets.addEmbeddedSignature(true, backSig);
                }
                catch (IOException e)
                {
                    throw new PGPException("Cannot encode embedded back-sig.");
                }
            }
            hashedSubpackets = parameters.applyToHashedSubpackets(hashedSubpackets);
            subKeySigGen.setHashedSubpackets(hashedSubpackets.generate());

            // Unhashed subpackets
            PGPSignatureSubpacketGenerator unhashedSubpackets = new PGPSignatureSubpacketGenerator();
            unhashedSubpackets = parameters.applyToUnhashedSubpackets(unhashedSubpackets);
            subKeySigGen.setUnhashedSubpackets(unhashedSubpackets.generate());

            // Inject signature into the certificate
            PGPPublicKey publicSubKey = signingSubkey.getPublicKey();
            PGPSignature subKeySig = subKeySigGen.generateCertification(publicPrimaryKey, publicSubKey);
            publicSubKey = PGPPublicKey.addCertification(publicSubKey, subKeySig);
            PGPSecretKey secretSubkey = new PGPSecretKey(
                    signingSubkey.getPrivateKey(),
                    publicSubKey,
                    implementation.pgpDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                    false,
                    null);
            PGPSecretKeyRing secretKeyRing = PGPSecretKeyRing.insertSecretKey(key.getPGPKeyRing(), secretSubkey);

            this.key = new OpenPGPKey(secretKeyRing, implementation, policy);
        }

        return this;
    }

    public OpenPGPKeyEditor revokeComponentKey(OpenPGPCertificate.OpenPGPComponentKey componentKey)
            throws PGPException
    {
        return revokeComponentKey(componentKey, null);
    }

    public OpenPGPKeyEditor revokeComponentKey(OpenPGPCertificate.OpenPGPComponentKey componentKey,
                                               SignatureParameters.Callback revocationSignatureCallback)
            throws PGPException
    {
        boolean contained = key.getKey(componentKey.getKeyIdentifier()) != null;
        if (!contained)
        {
            throw new IllegalArgumentException("Provided component key is not part of the OpenPGP key.");
        }

        boolean isSubkeyRevocation = !componentKey.getKeyIdentifier().equals(key.getKeyIdentifier());
        SignatureParameters parameters;
        if (isSubkeyRevocation)
        {
            // Generate Subkey Revocation Signature
            parameters = SignatureParameters.subkeyRevocation(policy);
        }
        else
        {
            // Generate Key Revocation Signature
            parameters = SignatureParameters.keyRevocation(policy);
        }

        if (revocationSignatureCallback != null)
        {
            parameters = revocationSignatureCallback.apply(parameters);
        }

        PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();
        PGPSignatureGenerator revGen = new PGPSignatureGenerator(
                implementation.pgpContentSignerBuilder(
                        publicPrimaryKey.getAlgorithm(),
                        parameters.getSignatureHashAlgorithmId()),
                publicPrimaryKey);
        revGen.init(parameters.getSignatureType(), primaryKey.getKeyPair().getPrivateKey());

        // Hashed subpackets
        PGPSignatureSubpacketGenerator hashedSubpackets = new PGPSignatureSubpacketGenerator();
        hashedSubpackets.setIssuerFingerprint(true, publicPrimaryKey);
        hashedSubpackets.setSignatureCreationTime(parameters.getSignatureCreationTime());
        hashedSubpackets = parameters.applyToHashedSubpackets(hashedSubpackets);
        revGen.setHashedSubpackets(hashedSubpackets.generate());

        // Unhashed subpackets
        PGPSignatureSubpacketGenerator unhashedSubpackets = new PGPSignatureSubpacketGenerator();
        unhashedSubpackets = parameters.applyToUnhashedSubpackets(unhashedSubpackets);
        revGen.setUnhashedSubpackets(unhashedSubpackets.generate());

        if (isSubkeyRevocation)
        {
            PGPPublicKey revokedKey = componentKey.getPGPPublicKey();
            PGPSignature revocation = revGen.generateCertification(publicPrimaryKey, revokedKey);
            revokedKey = PGPPublicKey.addCertification(revokedKey, revocation);
            PGPPublicKeyRing publicKeyRing = PGPPublicKeyRing.insertPublicKey(key.getPGPPublicKeyRing(), revokedKey);
            PGPSecretKeyRing secretKeyRing = PGPSecretKeyRing.replacePublicKeys(key.getPGPKeyRing(), publicKeyRing);
            this.key = new OpenPGPKey(secretKeyRing, implementation, policy);
        }
        else
        {
            PGPSignature revocation = revGen.generateCertification(publicPrimaryKey);
            publicPrimaryKey = PGPPublicKey.addCertification(publicPrimaryKey, revocation);
            PGPPublicKeyRing publicKeyRing = PGPPublicKeyRing.insertPublicKey(key.getPGPPublicKeyRing(), publicPrimaryKey);
            PGPSecretKeyRing secretKeyRing = PGPSecretKeyRing.replacePublicKeys(key.getPGPKeyRing(), publicKeyRing);
            this.key = new OpenPGPKey(secretKeyRing, implementation, policy);
        }

        return this;
    }

    public OpenPGPKeyEditor revokeKey()
            throws PGPException
    {
        return revokeKey(null);
    }

    public OpenPGPKeyEditor revokeKey(SignatureParameters.Callback revocationSignatureCallback)
            throws PGPException
    {
        return revokeComponentKey(key.getPrimaryKey(), revocationSignatureCallback);
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

        OpenPGPKey.OpenPGPPrivateKey privateKey = secretKey.unlock(oldPassphrase);
        secretKey = privateKey.changePassphrase(newPassphrase, implementation, useAEAD);

        key.replaceSecretKey(secretKey);
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

}
