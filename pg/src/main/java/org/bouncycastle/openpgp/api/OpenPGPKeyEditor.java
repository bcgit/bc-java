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

    public OpenPGPKeyEditor addUserId(String userId, char[] primaryKeyPassphrase)
            throws PGPException
    {
        return addUserId(userId, primaryKeyPassphrase, null);
    }

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

    public OpenPGPKeyEditor changePassphrase(OpenPGPCertificate.OpenPGPComponentKey subkey,
                                             char[] oldPassphrase,
                                             char[] newPassphrase,
                                             boolean useAEAD)
    {
        OpenPGPKey.OpenPGPSecretKey secretKey = key.getSecretKey(subkey);
        if (secretKey == null)
        {
            throw new IllegalArgumentException("Subkey is not part of the key.");
        }

        try
        {
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
        }
        catch (PGPException e)
        {
            throw new RuntimeException(e);
        }
        return this;
    }

    public OpenPGPKey done()
    {
        return key;
    }

    public OpenPGPKeyEditor revokeUserId(OpenPGPCertificate.OpenPGPUserId userId,
                                         char[] primaryKeyPassphrase)
            throws PGPException
    {
        return revokeUserId(userId, primaryKeyPassphrase, null);
    }

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
