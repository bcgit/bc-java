package org.bouncycastle.openpgp.api;

import java.util.Date;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.KeyIdentifier;
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
        SignatureParameters parameters = Utils.applySignatureParameters(signatureCallback,
            SignatureParameters.directKeySignature(policy));

        if (parameters != null)
        {
            PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();

            PGPSignatureGenerator dkSigGen = Utils.getPgpSignatureGenerator(implementation, publicPrimaryKey,
                primaryKey.getKeyPair().getPrivateKey(), parameters, parameters.getSignatureCreationTime(), null);

            PGPPublicKey pubKey = Utils.injectCertification(publicPrimaryKey, dkSigGen);
            this.key = generateOpenPGPKey(pubKey);
        }
        return this;
    }

    /**
     * Add a user-id to the primary key.
     * If the key already contains the given user-id, a new certification signature will be added to the user-id.
     *
     * @param userId user-id
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
     * @param userId            user-id
     * @param signatureCallback callback to modify the certification signature contents
     * @return this
     * @throws PGPException if the key cannot be modified
     */
    public OpenPGPKeyEditor addUserId(String userId,
                                      SignatureParameters.Callback signatureCallback)
        throws PGPException
    {
        // care needs to run with Java 5
        if (userId == null || userId.trim().length() == 0)
        {
            throw new IllegalArgumentException("User-ID cannot be null or empty.");
        }

        SignatureParameters parameters = Utils.applySignatureParameters(signatureCallback,
            SignatureParameters.certification(policy));

        if (parameters != null)
        {
            PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();

            PGPSignatureGenerator uidSigGen = Utils.getPgpSignatureGenerator(implementation, publicPrimaryKey,
                primaryKey.getKeyPair().getPrivateKey(), parameters, parameters.getSignatureCreationTime(), null);

            this.key = generateOpenPGPKey(Utils.injectCertification(userId, publicPrimaryKey, uidSigGen));
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
     * @param identity          user-id to revoke
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

        SignatureParameters parameters = Utils.applySignatureParameters(signatureCallback,
            SignatureParameters.certificationRevocation(policy));

        if (parameters != null)
        {
            PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();

            PGPSignatureGenerator idSigGen = Utils.getPgpSignatureGenerator(implementation, publicPrimaryKey,
                primaryKey.getKeyPair().getPrivateKey(), parameters, parameters.getSignatureCreationTime(), null);

            // Inject signature into the certificate
            PGPPublicKey pubKey;
            if (identity instanceof OpenPGPCertificate.OpenPGPUserId)
            {
                OpenPGPCertificate.OpenPGPUserId userId = (OpenPGPCertificate.OpenPGPUserId)identity;
                pubKey = Utils.injectCertification(userId.getUserId(), publicPrimaryKey, idSigGen);
            }
            else
            {
                OpenPGPCertificate.OpenPGPUserAttribute userAttribute = (OpenPGPCertificate.OpenPGPUserAttribute)identity;
                PGPSignature uattrSig = idSigGen.generateCertification(userAttribute.getUserAttribute(), publicPrimaryKey);
                pubKey = PGPPublicKey.addCertification(publicPrimaryKey, userAttribute.getUserAttribute(), uattrSig);
            }
            this.key = generateOpenPGPKey(pubKey);
        }
        return this;
    }

    public OpenPGPKeyEditor addEncryptionSubkey()
        throws PGPException
    {
        return addEncryptionSubkey(KeyPairGeneratorCallback.Util.encryptionKey());
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
        if (!encryptionSubkey.getPublicKey().isEncryptionKey())
        {
            throw new PGPKeyValidationException("Provided subkey is not encryption-capable.");
        }

        updateKey(encryptionSubkey, bindingSigCallback, key.getPrimaryKey().getPGPPublicKey(), new Utils.HashedSubpacketsOperation()
        {
            @Override
            public void operate(PGPSignatureSubpacketGenerator hashedSubpackets)
                throws PGPException
            {
                hashedSubpackets.setKeyFlags(KeyFlags.ENCRYPT_STORAGE | KeyFlags.ENCRYPT_COMMS);
            }
        });

        return this;
    }

    public OpenPGPKeyEditor addSigningSubkey()
        throws PGPException
    {
        return addSigningSubkey(KeyPairGeneratorCallback.Util.signingKey());
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

        SignatureParameters backSigParameters = Utils.applySignatureParameters(backSigCallback,
            SignatureParameters.primaryKeyBinding(policy));

        PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();

        final PGPSignature backSig = Utils.getBackSignature(signingSubkey, backSigParameters, publicPrimaryKey, implementation, null);

        updateKey(signingSubkey, bindingSigCallback, publicPrimaryKey, new Utils.HashedSubpacketsOperation()
        {
            @Override
            public void operate(PGPSignatureSubpacketGenerator hashedSubpackets)
                throws PGPException
            {
                hashedSubpackets.setKeyFlags(KeyFlags.SIGN_DATA);
                Utils.addEmbeddedSiganture(backSig, hashedSubpackets);
            }
        });

        return this;
    }

    /**
     * Add a component key to the certificate.
     * The bindingSigCallback can be used to modify the subkey binding signature.
     * If it is null, no subkey binding signature will be generated.
     * The backSigCallback can be used to modify the embedded primary key binding signature.
     * If it is null, no primary key binding signature will be generated.
     * You MUST only pass a non-null value here, if the subkey is capable of creating signatures.
     *
     * @param subkey             component key
     * @param bindingSigCallback callback to modify the subkey binding signature
     * @param backSigCallback    callback to modify the embedded primary key binding signature
     * @return this
     * @throws PGPException
     */
    public OpenPGPKeyEditor addSubkey(PGPKeyPair subkey,
                                      SignatureParameters.Callback bindingSigCallback,
                                      SignatureParameters.Callback backSigCallback)
        throws PGPException
    {
        if (PublicKeyUtils.isSigningAlgorithm(subkey.getPublicKey().getAlgorithm())
            && backSigCallback != null)
        {
            throw new PGPKeyValidationException("Provided subkey is not signing-capable, so we cannot create a back-signature.");
        }

        PGPPublicKey publicSubKey = subkey.getPublicKey();

        SignatureParameters backSigParameters = Utils.applySignatureParameters(backSigCallback,
            SignatureParameters.primaryKeyBinding(policy));

        PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();

        final PGPSignature backSig = Utils.getBackSignature(subkey, backSigParameters, publicPrimaryKey, implementation, null);

        SignatureParameters parameters = Utils.applySignatureParameters(bindingSigCallback,
            SignatureParameters.subkeyBinding(policy));

        if (parameters != null)
        {
            PGPSignatureGenerator subKeySigGen = Utils.getPgpSignatureGenerator(implementation, publicPrimaryKey,
                primaryKey.getKeyPair().getPrivateKey(), parameters, parameters.getSignatureCreationTime(),
                new Utils.HashedSubpacketsOperation()
                {
                    @Override
                    public void operate(PGPSignatureSubpacketGenerator hashedSubpackets)
                        throws PGPException
                    {
                        Utils.addEmbeddedSiganture(backSig, hashedSubpackets);
                    }
                });

            // Inject signature into the certificate
            publicSubKey = Utils.injectCertification(publicSubKey, subKeySigGen, publicPrimaryKey);
        }

        this.key = generateOpenPGPKey(subkey, publicSubKey);

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

        parameters = Utils.applySignatureParameters(revocationSignatureCallback, parameters);

        PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();
        PGPSignatureGenerator revGen = Utils.getPgpSignatureGenerator(implementation, publicPrimaryKey,
            primaryKey.getKeyPair().getPrivateKey(), parameters, parameters.getSignatureCreationTime(), null);

        if (isSubkeyRevocation)
        {
            publicPrimaryKey = Utils.injectCertification(componentKey.getPGPPublicKey(), revGen, publicPrimaryKey);
        }
        else
        {
            publicPrimaryKey = Utils.injectCertification(publicPrimaryKey, revGen);
        }
        this.key = generateOpenPGPKey(publicPrimaryKey);

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
     * @param componentKeyIdentifier identifier of the component key, whose passphrase shall be changed
     * @param oldPassphrase          old passphrase (or null)
     * @param newPassphrase          new passphrase (or null)
     * @param useAEAD                whether to use AEAD
     * @return this
     * @throws OpenPGPKeyException if the secret component of the component key is missing
     * @throws PGPException        if the key passphrase cannot be changed
     */
    public OpenPGPKeyEditor changePassphrase(KeyIdentifier componentKeyIdentifier,
                                             char[] oldPassphrase,
                                             char[] newPassphrase,
                                             boolean useAEAD)
        throws OpenPGPKeyException, PGPException
    {
        OpenPGPKey.OpenPGPSecretKey secretKey = key.getSecretKey(componentKeyIdentifier);
        if (secretKey == null)
        {
            throw new OpenPGPKeyException(key, "Secret component key " + componentKeyIdentifier +
                " is missing from the key.");
        }

        OpenPGPKey.OpenPGPPrivateKey privateKey = secretKey.unlock(oldPassphrase);
        secretKey = privateKey.changePassphrase(newPassphrase, implementation, useAEAD);

        key.replaceSecretKey(secretKey);
        return this;
    }

    /**
     * Return the modified {@link OpenPGPKey}.
     *
     * @return modified key
     */
    public OpenPGPKey done()
    {
        return key;
    }

    private OpenPGPKey generateOpenPGPKey(PGPPublicKey publicPrimaryKey)
    {
        PGPPublicKeyRing publicKeyRing = PGPPublicKeyRing.insertPublicKey(key.getPGPPublicKeyRing(), publicPrimaryKey);
        PGPSecretKeyRing secretKeyRing = PGPSecretKeyRing.replacePublicKeys(key.getPGPKeyRing(), publicKeyRing);
        return new OpenPGPKey(secretKeyRing, implementation, policy);
    }

    private OpenPGPKey generateOpenPGPKey(PGPKeyPair subkey, PGPPublicKey publicSubKey)
        throws PGPException
    {
        PGPSecretKey secretSubkey = new PGPSecretKey(
            subkey.getPrivateKey(),
            publicSubKey,
            implementation.pgpDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            false,
            null);
        PGPSecretKeyRing secretKeyRing = PGPSecretKeyRing.insertSecretKey(key.getPGPKeyRing(), secretSubkey);
        return new OpenPGPKey(secretKeyRing, implementation, policy);
    }

    private void updateKey(PGPKeyPair subkey, SignatureParameters.Callback bindingSigCallback, PGPPublicKey publicPrimaryKey, Utils.HashedSubpacketsOperation operation)
        throws PGPException
    {
        SignatureParameters parameters = Utils.applySignatureParameters(bindingSigCallback,
            SignatureParameters.subkeyBinding(policy));

        if (parameters != null)
        {
            PGPSignatureGenerator subKeySigGen = Utils.getPgpSignatureGenerator(implementation, publicPrimaryKey,
                primaryKey.getKeyPair().getPrivateKey(), parameters, parameters.getSignatureCreationTime(),
                operation);

            PGPPublicKey publicSubKey = Utils.injectCertification(subkey.getPublicKey(), subKeySigGen, publicPrimaryKey);
            this.key = generateOpenPGPKey(subkey, publicSubKey);
        }
    }
}
