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

import java.util.Date;

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

    public OpenPGPKeyEditor addUserId(String userId, char[] primaryKeyPassphrase)
            throws PGPException
    {
        return addUserId(userId, PGPSignature.POSITIVE_CERTIFICATION, null, HashAlgorithmTags.SHA3_512, new Date(), primaryKeyPassphrase);
    }

    public OpenPGPKeyEditor addUserId(String userId,
                                      int certificationType,
                                      SignatureSubpacketsFunction userIdSubpackets,
                                      int hashAlgorithmId,
                                      Date bindingTime,
                                      char[] primaryKeyPassphrase)
            throws PGPException
    {
        if (userId == null || userId.trim().isEmpty())
        {
            throw new IllegalArgumentException("User-ID cannot be null or empty.");
        }

        if (!PGPSignature.isCertification(certificationType))
        {
            throw new IllegalArgumentException("Signature type MUST be a certification type (0x10 - 0x13)");
        }

        PGPPublicKey publicPrimaryKey = key.getPrimaryKey().getPGPPublicKey();
        PGPPrivateKey privatePrimaryKey = key.getPrimarySecretKey().unlock(primaryKeyPassphrase);

        PGPSignatureGenerator uidSigGen = new PGPSignatureGenerator(
                implementation.pgpContentSignerBuilder(publicPrimaryKey.getAlgorithm(), hashAlgorithmId),
                publicPrimaryKey);
        uidSigGen.init(certificationType, privatePrimaryKey);

        PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();
        subpackets.setIssuerFingerprint(true, publicPrimaryKey);
        subpackets.setSignatureCreationTime(bindingTime);

        if (userIdSubpackets != null)
        {
            subpackets = userIdSubpackets.apply(subpackets);
        }
        uidSigGen.setHashedSubpackets(subpackets.generate());

        PGPSignature uidSig = uidSigGen.generateCertification(userId, publicPrimaryKey);
        PGPPublicKey pubKey = PGPPublicKey.addCertification(publicPrimaryKey, userId, uidSig);
        PGPPublicKeyRing publicKeyRing = PGPPublicKeyRing.insertPublicKey(key.getPGPPublicKeyRing(), pubKey);
        PGPSecretKeyRing secretKeyRing = PGPSecretKeyRing.replacePublicKeys(key.getPGPKeyRing(), publicKeyRing);

        this.key = new OpenPGPKey(secretKeyRing, implementation, policy);
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
        } catch (PGPException e) {
            throw new RuntimeException(e);
        }
        return this;
    }

    public OpenPGPKey done()
    {
        return key;
    }
}
