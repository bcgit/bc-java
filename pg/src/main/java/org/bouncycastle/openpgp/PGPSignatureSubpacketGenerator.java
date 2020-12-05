package org.bouncycastle.openpgp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.EmbeddedSignature;
import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IntendedRecipientFingerprint;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.Revocable;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.bcpg.sig.RevocationKeyTags;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.SignatureTarget;
import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.bcpg.sig.TrustSignature;

/**
 * Generator for signature subpackets.
 */
public class PGPSignatureSubpacketGenerator
{
    private SignatureCreationTime signatureCreationTime;
    private SignatureExpirationTime signatureExpirationTime;
    private Exportable exportableCertification;
    private TrustSignature trustSignature;
    private Revocable revocable;
    private KeyExpirationTime keyExpirationTime;
    private PreferredAlgorithms preferredSymmetricAlgorithms;
    private final List<RevocationKey> revocationKeys = new ArrayList<RevocationKey>();
    private IssuerKeyID issuerKeyID;
    private final List<NotationData> notations = new ArrayList<NotationData>();
    private PreferredAlgorithms preferredHashAlgorithms;
    private PreferredAlgorithms preferredCompressionAlgorithms;
    private PrimaryUserID primaryUserID;
    private KeyFlags keyFlags;
    private final List<SignerUserID> signerUserIDs = new ArrayList<SignerUserID>();
    private RevocationReason revocationReason;
    private Features features;
    private SignatureTarget signatureTarget;
    private final List<EmbeddedSignature> embeddedSignatures = new ArrayList<EmbeddedSignature>();
    private IssuerFingerprint issuerFingerprint;
    private final List<IntendedRecipientFingerprint> intendedRecipientFingerprints = new ArrayList<IntendedRecipientFingerprint>();
    private final List<SignatureSubpacket> miscellaneousSubpackets = new ArrayList<SignatureSubpacket>();

    public PGPSignatureSubpacketGenerator()
    {
    }

    /**
     * Create a new signature subpacket generator that preserves the (known) subpackets of the given vector.
     *
     * @param vector signature subpacket vector
     * @throws PGPException in case an unsupported critical subpacket is encountered.
     */
    public PGPSignatureSubpacketGenerator(PGPSignatureSubpacketVector vector) throws PGPException {
        for (SignatureSubpacket subpacket : vector.packets) {
            addSubpacket(subpacket);
        }
    }

    public void addSubpacket(SignatureSubpacket subpacket) throws PGPException {
        switch (subpacket.getType()) {
            case SignatureSubpacketTags.CREATION_TIME:
                signatureCreationTime = (SignatureCreationTime) subpacket;
                break;
            case SignatureSubpacketTags.EXPIRE_TIME:
                signatureExpirationTime = (SignatureExpirationTime) subpacket;
                break;
            case SignatureSubpacketTags.EXPORTABLE:
                exportableCertification = (Exportable) subpacket;
                break;
            case SignatureSubpacketTags.TRUST_SIG:
                trustSignature = (TrustSignature) subpacket;
                break;
            case SignatureSubpacketTags.REVOCABLE:
                revocable = (Revocable) subpacket;
                break;
            case SignatureSubpacketTags.KEY_EXPIRE_TIME:
                keyExpirationTime = (KeyExpirationTime) subpacket;
                break;
            case SignatureSubpacketTags.PREFERRED_SYM_ALGS:
                preferredSymmetricAlgorithms = (PreferredAlgorithms) subpacket;
                break;
            case SignatureSubpacketTags.REVOCATION_KEY:
                revocationKeys.add((RevocationKey) subpacket);
                break;
            case SignatureSubpacketTags.ISSUER_KEY_ID:
                issuerKeyID = (IssuerKeyID) subpacket;
                break;
            case SignatureSubpacketTags.NOTATION_DATA:
                notations.add((NotationData) subpacket);
                break;
            case SignatureSubpacketTags.PREFERRED_HASH_ALGS:
                preferredHashAlgorithms = (PreferredAlgorithms) subpacket;
                break;
            case SignatureSubpacketTags.PREFERRED_COMP_ALGS:
                preferredCompressionAlgorithms = (PreferredAlgorithms) subpacket;
                break;
            case SignatureSubpacketTags.PRIMARY_USER_ID:
                primaryUserID = (PrimaryUserID) subpacket;
                break;
            case SignatureSubpacketTags.KEY_FLAGS:
                keyFlags = (KeyFlags) subpacket;
                break;
            case SignatureSubpacketTags.SIGNER_USER_ID:
                signerUserIDs.add((SignerUserID) subpacket);
                break;
            case SignatureSubpacketTags.REVOCATION_REASON:
                revocationReason = (RevocationReason) subpacket;
                break;
            case SignatureSubpacketTags.FEATURES:
                features = (Features) subpacket;
                break;
            case SignatureSubpacketTags.SIGNATURE_TARGET:
                signatureTarget = (SignatureTarget) subpacket;
                break;
            case SignatureSubpacketTags.EMBEDDED_SIGNATURE:
                embeddedSignatures.add((EmbeddedSignature) subpacket);
                break;
            case SignatureSubpacketTags.ISSUER_FINGERPRINT:
                issuerFingerprint = (IssuerFingerprint) subpacket;
                break;
            case SignatureSubpacketTags.INTENDED_RECIPIENT_FINGERPRINT:
                intendedRecipientFingerprints.add((IntendedRecipientFingerprint) subpacket);
                break;
            default:
                if (subpacket.isCritical()) {
                    throw new PGPException("Critical unknown subpacket detected (" + subpacket.getType() + ")");
                } else {
                    addMiscellaneousSubpacket(subpacket);
                }
        }
    }

    /**
     * Specify, whether or not the signature is revocable.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param isRevocable true if the signature should be revocable, false otherwise.
     */
    public void setRevocable(boolean isCritical, boolean isRevocable)
    {
        revocable = new Revocable(isCritical, isRevocable);
    }

    /**
     * Specify, whether or not the signature should be marked as exportable.
     * If this subpacket is missing, the signature is treated as being exportable.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param isExportable true if the signature should be exportable, false otherwise.
     */
    public void setExportable(boolean isCritical, boolean isExportable)
    {
        exportableCertification = new Exportable(isCritical, isExportable);
    }

    /**
     * Specify the set of features of the key.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param feature features
     */
    public void setFeature(boolean isCritical, byte feature)
    {
        features = new Features(isCritical, feature);
    }

    /**
     * Add a TrustSignature packet to the signature. The values for depth and trust are
     * largely installation dependent but there are some guidelines in RFC 4880 -
     * 5.2.3.13.
     *
     * @param isCritical  true if the packet is critical.
     * @param depth       depth level.
     * @param trustAmount trust amount.
     */
    public void setTrust(boolean isCritical, int depth, int trustAmount)
    {
        trustSignature = new TrustSignature(isCritical, depth, trustAmount);
    }

    /**
     * Set the trust packet of the signature to {@code null}.
     */
    public void clearTrust()
    {
        trustSignature = null;
    }

    /**
     * Set the number of seconds a key is valid for after the time of its creation. A
     * value of zero means the key never expires.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param seconds seconds that the key is valid for after creation
     */
    public void setKeyExpirationTime(boolean isCritical, long seconds)
    {
        keyExpirationTime = new KeyExpirationTime(isCritical, seconds);
    }

    /**
     * Set the expiration time subpacket of the signature to {@code null}.
     */
    public void clearKeyExpirationTime()
    {
        keyExpirationTime = null;
    }

    /**
     * Set the number of seconds a signature is valid for after the time of its creation.
     * A value of zero means the signature never expires.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param seconds seconds that the signature is valid for after creation
     */
    public void setSignatureExpirationTime(boolean isCritical, long seconds)
    {
        signatureExpirationTime = new SignatureExpirationTime(isCritical, seconds);
    }

    /**
     * Set the expiration time subpacket of the signature to {@code null}.
     */
    public void clearSignatureExpirationTime()
    {
        signatureExpirationTime = null;
    }

    /**
     * Set the creation time for the signature.
     * <p>
     * Note: this overrides the generation of a creation time when the signature is
     * generated.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param date date on which the signature was created
     */
    public void setSignatureCreationTime(boolean isCritical, Date date)
    {
        signatureCreationTime = new SignatureCreationTime(isCritical, date);
    }

    /**
     * Set the creation time of the signature to {@code null}.
     * <p>
     * Note: This does not prevent a creation time packet from being set automatically.
     */
    public void clearSignatureCreationTime()
    {
        signatureExpirationTime = null;
    }

    /**
     * Specify the preferred hash algorithms of the key.
     * See {@link org.bouncycastle.bcpg.HashAlgorithmTags}.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param algorithms array of algorithms in descending preference
     */
    public void setPreferredHashAlgorithms(boolean isCritical, int[] algorithms)
    {
        preferredHashAlgorithms = new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_HASH_ALGS,
                isCritical, algorithms);
    }

    /**
     * Set the preferred hash algorithms subpacket to {@code null}.
     */
    public void clearPreferredHashAlgorithms()
    {
        preferredHashAlgorithms = null;
    }

    /**
     * Specify the preferred symmetric encryption algorithms of the key.
     * See {@link org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags}.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param algorithms array of algorithms in descending preference
     */
    public void setPreferredSymmetricAlgorithms(boolean isCritical, int[] algorithms)
    {
        preferredSymmetricAlgorithms = new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_SYM_ALGS,
                isCritical, algorithms);
    }

    /**
     * Set the preferred symmetric algorithms subpacket to {@code null}.
     */
    public void clearPreferredSymmetricAlgorithms()
    {
        preferredSymmetricAlgorithms = null;
    }

    /**
     * Specify the preferred compression algorithms of this key.
     * See {@link org.bouncycastle.bcpg.CompressionAlgorithmTags}.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param algorithms array of algorithms in descending preference
     */
    public void setPreferredCompressionAlgorithms(boolean isCritical, int[] algorithms)
    {
        preferredCompressionAlgorithms = new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_COMP_ALGS,
                isCritical, algorithms);
    }

    /**
     * Set the preferred compression algorithms subpacket to {@code null}.
     */
    public void clearPreferredCompressionAlgorithms()
    {
        preferredCompressionAlgorithms = null;
    }

    /**
     * Set this keys key flags.
     * See {@link PGPKeyFlags}.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param flags flags
     */
    public void setKeyFlags(boolean isCritical, int flags)
    {
        keyFlags = new KeyFlags(isCritical, flags);
    }

    /**
     * Set the key flags subpacket to {@code null}.
     */
    public void clearKeyFlags()
    {
        keyFlags = null;
    }

    /**
     * Add a signer user-id to the signature.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param userID signer user-id
     *
     * @deprecated use {@link #addSignerUserID(boolean, String)} instead.
     */
    @Deprecated
    public void setSignerUserID(boolean isCritical, String userID)
    {
        addSignerUserID(isCritical, userID);
    }

    /**
     * Add a signer user-id to the signature.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param userID signer user-id
     */
    public void addSignerUserID(boolean isCritical, String userID)
    {
        if (userID == null)
        {
            throw new IllegalArgumentException("attempt to set null SignerUserID");
        }

        signerUserIDs.add(new SignerUserID(isCritical, userID));
    }

    /**
     * Add a signer user-id to the signature.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param rawUserID signer user-id
     *
     * @deprecated use {@link #addSignerUserID(boolean, byte[])} instead.
     */
    @Deprecated
    public void setSignerUserID(boolean isCritical, byte[] rawUserID)
    {
        addSignerUserID(isCritical, rawUserID);
    }

    /**
     * Add a signer user-id to the signature.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param rawUserID signer user-id
     */
    public void addSignerUserID(boolean isCritical, byte[] rawUserID)
    {
        if (rawUserID == null)
        {
            throw new IllegalArgumentException("attempt to set null SignerUserID");
        }

        signerUserIDs.add(new SignerUserID(isCritical, false, rawUserID));
    }

    /**
     * Clear the list of signer user-ids.
     */
    public void clearSignerUserIDs()
    {
        signerUserIDs.clear();
    }

    /**
     * Add an embedded signature packet.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param pgpSignature embedded signature
     * @throws IOException in case of an error
     *
     * @deprecated use {@link #addEmbeddedSignature(boolean, PGPSignature)} instead.
     */
    @Deprecated
    public void setEmbeddedSignature(boolean isCritical, PGPSignature pgpSignature)
            throws IOException
    {
        addEmbeddedSignature(isCritical, pgpSignature);
    }

    /**
     * Add an embedded signature packet.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param pgpSignature embedded signature
     * @throws IOException in case of an error
     */
    public void addEmbeddedSignature(boolean isCritical, PGPSignature pgpSignature)
        throws IOException
    {
        byte[] sig = pgpSignature.getEncoded();
        byte[] data;

        if (sig.length - 1 > 256)
        {
            data = new byte[sig.length - 3];
        }
        else
        {
            data = new byte[sig.length - 2];
        }

        System.arraycopy(sig, sig.length - data.length, data, 0, data.length);

        embeddedSignatures.add(new EmbeddedSignature(isCritical, false, data));
    }

    /**
     * Clear the list of embedded signatures.
     */
    public void clearEmbeddedSignatures()
    {
        embeddedSignatures.clear();
    }

    /**
     * Specify, whether or not the self-signature marks the primary userID of the key.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param isPrimaryUserID true if the user-id is primary, false otherwise
     */
    public void setPrimaryUserID(boolean isCritical, boolean isPrimaryUserID)
    {
        primaryUserID = new PrimaryUserID(isCritical, isPrimaryUserID);
    }

    /**
     * Set the primary user-id subpacket of the signature to {@code null}.
     */
    public void clearPrimaryUserID()
    {
        primaryUserID = null;
    }

    /**
     * Add a notation data packet to the signature.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param isHumanReadable true if the notation is human-readable.
     * @param notationName name of the notation key
     * @param notationValue value of the notation
     *
     * @deprecated use {@link #addNotationData(boolean, boolean, String, String)} instead.
     */
    @Deprecated
    public void setNotationData(boolean isCritical, boolean isHumanReadable, String notationName,
                                String notationValue)
    {
        addNotationData(isCritical, isHumanReadable, notationName, notationValue);
    }

    /**
     * Add a notation data packet to the signature.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param isHumanReadable true if the notation is human-readable.
     * @param notationName name of the notation key.
     * @param notationValue value of the notation.
     */
    public void addNotationData(boolean isCritical, boolean isHumanReadable, String notationName,
                                String notationValue)
    {
        notations.add(new NotationData(isCritical, isHumanReadable, notationName, notationValue));
    }

    /**
     * Clear the list of notations on the signature.
     */
    public void clearNotationData()
    {
        notations.clear();
    }

    /**
     * Sets revocation reason sub packet.
     * See {@link org.bouncycastle.bcpg.sig.RevocationReasonTags}.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param reason reason code for the revocation
     * @param description human readable description of the revocation reason
     */
    public void setRevocationReason(boolean isCritical, byte reason, String description)
    {
        revocationReason = new RevocationReason(isCritical, reason, description);
    }

    /**
     * Set the revocation reason subpacket of the signature to {@code null}.
     */
    public void clearRevocationReason() {
        revocationReason = null;
    }

    /**
     * Adds a revocation key sub packet.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param keyAlgorithm algorithm of the revocation key
     * @param fingerprint fingerprint of the revocation key
     *
     * @deprecated use {@link #addRevocationKey(boolean, int, byte[])} instead.
     */
    @Deprecated
    public void setRevocationKey(boolean isCritical, int keyAlgorithm, byte[] fingerprint)
    {
        addRevocationKey(isCritical, keyAlgorithm, fingerprint);
    }

    /**
     * Adds a revocation key sub packet.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param keyAlgorithm algorithm of the revocation key
     * @param fingerprint fingerprint of the revocation key
     */
    public void addRevocationKey(boolean isCritical, int keyAlgorithm, byte[] fingerprint)
    {
        revocationKeys.add(new RevocationKey(isCritical, RevocationKeyTags.CLASS_DEFAULT, keyAlgorithm,
            fingerprint));
    }

    /**
     * Clear the list of revocation keys.
     */
    public void clearRevocationKeys()
    {
        revocationKeys.clear();
    }

    /**
     * Sets issuer key-id subpacket.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param keyID id of the key that issued the signature
     */
    public void setIssuerKeyID(boolean isCritical, long keyID)
    {
        issuerKeyID = new IssuerKeyID(isCritical, keyID);
    }

    /**
     * Set the issuer key-id subpacket to {@code null}.
     */
    public void clearIssuerKeyID()
    {
        issuerKeyID = null;
    }

    /**
     * Sets the signature target sub packet.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param publicKeyAlgorithm algorithm of the key that issued the signature that is being referred to.
     * @param hashAlgorithm hash algorithm that was used to calculate the hash data.
     * @param hashData hash of the signature that is being referred to.
     */
    public void setSignatureTarget(boolean isCritical, int publicKeyAlgorithm, int hashAlgorithm, byte[] hashData)
    {
        signatureTarget = new SignatureTarget(isCritical, publicKeyAlgorithm, hashAlgorithm, hashData);
    }

    /**
     * Set the signature target subpacket to {@code null}.
     */
    public void clearSignatureTarget()
    {
        signatureTarget = null;
    }

    /**
     * Sets the signature issuer fingerprint for the signing key.
     *
     * @param isCritical true if critical, false otherwise.
     * @param secretKey the secret key used to generate the associated signature.
     */
    public void setIssuerFingerprint(boolean isCritical, PGPSecretKey secretKey)
    {
        this.setIssuerFingerprint(isCritical, secretKey.getPublicKey());
    }

    /**
     * Sets the signature issuer fingerprint for the signing key.
     *
     * @param isCritical true if critical, false otherwise.
     * @param publicKey the public key needed to verify the associated signature.
     */
    public void setIssuerFingerprint(boolean isCritical, PGPPublicKey publicKey)
    {
        issuerFingerprint = new IssuerFingerprint(isCritical, publicKey.getVersion(), publicKey.getFingerprint());
    }

    /**
     * Set the issuer fingerprint subpacket to {@code null}.
     */
    public void clearIssuerFingerprint()
    {
        issuerFingerprint = null;
    }

    /**
     * Adds a intended recipient fingerprint for an encrypted payload the signature is associated with.
     *
     * @param isCritical true if critical, false otherwise.
     * @param publicKey the public key the encrypted payload was encrypted against.
     *
     * @deprecated use {@link #addIntendedRecipientFingerprint(boolean, PGPPublicKey)} instead.
     */
    @Deprecated
    public void setIntendedRecipientFingerprint(boolean isCritical, PGPPublicKey publicKey)
    {
        addIntendedRecipientFingerprint(isCritical, publicKey);
    }

    /**
     * Adds a intended recipient fingerprint for an encrypted payload the signature is associated with.
     *
     * @param isCritical true if critical, false otherwise.
     * @param publicKey the public key the encrypted payload was encrypted against.
     */
    public void addIntendedRecipientFingerprint(boolean isCritical, PGPPublicKey publicKey)
    {
        intendedRecipientFingerprints.add(new IntendedRecipientFingerprint(isCritical,
                publicKey.getVersion(), publicKey.getFingerprint()));
    }

    /**
     * Clear the list of intended recipient fingerprint subpackets.
     */
    public void clearIntendedRecipientFingerprints()
    {
        intendedRecipientFingerprints.clear();
    }

    /**
     * Add a miscellaneous subpacket.
     * Miscellaneous subpackets are subpackets that Bouncycastle does not recognize or
     * doesn't have first class support for.
     *
     * @param subpacket subpacket
     */
    private void addMiscellaneousSubpacket(SignatureSubpacket subpacket)
    {
        miscellaneousSubpackets.add(subpacket);
    }

    /**
     * Clear the list of miscellaneous subpackets.
     */
    public void clearMiscellaneousSubpackets()
    {
        miscellaneousSubpackets.clear();
    }

    /**
     * Generate the subpacket vector.
     *
     * @return signature subpacket vector.
     */
    public PGPSignatureSubpacketVector generate()
    {
        List<SignatureSubpacket> subpacketList = new ArrayList<SignatureSubpacket>();
        if (signatureCreationTime != null) subpacketList.add(signatureCreationTime);
        if (signatureExpirationTime != null) subpacketList.add(signatureExpirationTime);
        if (exportableCertification != null) subpacketList.add(exportableCertification);
        if (trustSignature != null) subpacketList.add(trustSignature);
        if (revocable != null) subpacketList.add(revocable);
        if (keyExpirationTime != null) subpacketList.add(keyExpirationTime);
        if (preferredSymmetricAlgorithms != null) subpacketList.add(preferredSymmetricAlgorithms);
        subpacketList.addAll(revocationKeys);
        if (issuerKeyID != null) subpacketList.add(issuerKeyID);
        subpacketList.addAll(notations);
        if (preferredHashAlgorithms != null) subpacketList.add(preferredHashAlgorithms);
        if (preferredCompressionAlgorithms != null) subpacketList.add(preferredCompressionAlgorithms);
        if (primaryUserID != null) subpacketList.add(primaryUserID);
        if (keyFlags != null) subpacketList.add(keyFlags);
        subpacketList.addAll(signerUserIDs);
        if (revocationReason != null) subpacketList.add(revocationReason);
        if (features != null) subpacketList.add(features);
        if (signatureTarget != null) subpacketList.add(signatureTarget);
        subpacketList.addAll(embeddedSignatures);
        if (issuerFingerprint != null) subpacketList.add(issuerFingerprint);
        subpacketList.addAll(intendedRecipientFingerprints);
        subpacketList.addAll(miscellaneousSubpackets);

        return new PGPSignatureSubpacketVector(
                subpacketList.toArray(new SignatureSubpacket[subpacketList.size()]));
    }
}
