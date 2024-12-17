package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;

import java.util.Date;

public class OpenPGPKeyEditor
    extends AbstractOpenPGPKeySignatureGenerator
{

    private final OpenPGPImplementation implementation;
    private OpenPGPKey key;

    public OpenPGPKeyEditor(OpenPGPKey key)
    {
        this(key, key.implementation);
    }

    public OpenPGPKeyEditor(OpenPGPKey key, OpenPGPImplementation implementation)
    {
        this.key = key;
        this.implementation = implementation;
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

        this.key = new OpenPGPKey(secretKeyRing, implementation);
        return this;
    }

    public OpenPGPKey done()
    {
        return key;
    }
}
