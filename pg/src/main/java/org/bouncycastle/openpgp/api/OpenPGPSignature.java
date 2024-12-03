package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.api.exception.MalformedPGPSignatureException;
import org.bouncycastle.openpgp.api.util.UTCUtil;
import org.bouncycastle.util.encoders.Hex;

import java.util.Date;
import java.util.List;

/**
 * An OpenPGP signature.
 * This is a wrapper around {@link PGPSignature} which tracks the verification state of the signature.
 */
public abstract class OpenPGPSignature
{
    protected final PGPSignature signature;
    protected final OpenPGPCertificate.OpenPGPComponentKey issuer;
    protected boolean isTested = false;
    protected boolean isCorrect = false;

    /**
     * Create an {@link OpenPGPSignature}.
     *
     * @param signature signature
     * @param issuer issuer subkey
     */
    public OpenPGPSignature(PGPSignature signature, OpenPGPCertificate.OpenPGPComponentKey issuer)
    {
        this.signature = signature;
        this.issuer = issuer;
    }

    /**
     * Return the {@link PGPSignature}.
     *
     * @return signature
     */
    public PGPSignature getSignature()
    {
        return signature;
    }

    /**
     * Return the {@link OpenPGPCertificate.OpenPGPComponentKey} subkey that issued this signature.
     * This method might return null, if the issuer certificate is not available.
     *
     * @return issuer subkey or null
     */
    public OpenPGPCertificate.OpenPGPComponentKey getIssuer()
    {
        return issuer;
    }

    /**
     * Return the {@link OpenPGPCertificate} that contains the subkey that issued this signature.
     * This method might return null if the issuer certificate is not available
     *
     * @return issuer certificate or null
     */
    public OpenPGPCertificate getIssuerCertificate()
    {
        return issuer != null ? issuer.getCertificate() : null;
    }

    /**
     * Return a {@link List} of possible {@link KeyIdentifier} candidates.
     *
     * @return key identifier candidates
     */
    public List<KeyIdentifier> getKeyIdentifiers()
    {
        return signature.getKeyIdentifiers();
    }

    /**
     * Return the most expressive {@link KeyIdentifier} from available candidates.
     *
     * @return most expressive key identifier
     */
    public KeyIdentifier getKeyIdentifier()
    {
        List<KeyIdentifier> identifiers = getKeyIdentifiers();
        return getMostExpressiveIdentifier(identifiers);
    }

    /**
     * Return the most expressive issuer {@link KeyIdentifier}.
     * Due to historic reasons, signatures MAY contain more than one issuer packet, which might contain inconsistent
     * information (issuer key-ids / issuer fingerprints).
     * Throw wildcards (anonymous issuers) into the mix, and it becomes apparent, that there needs to be a way to
     * select the "best" issuer identifier.
     * If there are more than one issuer packet, this method returns the most expressive (prefer fingerprints over
     * key-ids, prefer non-wildcard over wildcard) and returns that.
     *
     * @param identifiers list of available identifiers
     * @return the best identifier
     */
    public static KeyIdentifier getMostExpressiveIdentifier(List<KeyIdentifier> identifiers)
    {
        if (identifiers.isEmpty())
        {
            // none
            return null;
        }
        if (identifiers.size() == 1)
        {
            // single
            return identifiers.get(0);
        }

        // Find most expressive identifier
        for (KeyIdentifier identifier : identifiers)
        {
            // non-wildcard and has fingerprint
            if (!identifier.isWildcard() && identifier.getFingerprint() != null)
            {
                return identifier;
            }
        }

        // Find non-wildcard identifier
        for (KeyIdentifier identifier : identifiers)
        {
            // non-wildcard (and no fingerprint)
            if (!identifier.isWildcard())
            {
                return identifier;
            }
        }
        // else return first identifier
        return identifiers.get(0);
    }

    /**
     * Return true, if this signature has been tested and is correct.
     *
     * @return true if the signature is tested and is correct, false otherwise
     */
    public boolean isTestedCorrect()
    {
        return isTested && isCorrect;
    }

    /**
     * Return the creation time of the signature.
     *
     * @return signature creation time
     */
    public Date getCreationTime()
    {
        return signature.getCreationTime();
    }

    /**
     * Return the expiration time of the signature.
     * If no expiration time was included (or if the signature was explicitly marked as non-expiring),
     * return null, otherwise return the time of expiration.
     * The signature is no longer valid, once the expiration time is exceeded.
     *
     * @return expiration time
     */
    public Date getExpirationTime()
    {
        PGPSignatureSubpacketVector hashed = signature.getHashedSubPackets();
        if (hashed == null)
        {
            // v3 sigs have no expiration
            return null;
        }
        long exp = hashed.getSignatureExpirationTime();
        if (exp < 0)
        {
            throw new RuntimeException("Negative expiration time");
        }

        if (exp == 0L)
        {
            // Explicit or implicit no expiration
            return null;
        }

        return new Date(getCreationTime().getTime() + 1000 * exp);
    }

    /**
     * Return true, if the signature is not a hard revocation, and if the evaluation time falls into the period
     * between signature creation time and expiration or revocation.
     *
     * @param evaluationTime time for which you want to determine effectiveness of the signature
     * @return true if the signature is effective at the given evaluation time
     */
    public boolean isEffectiveAt(Date evaluationTime)
    {
        if (isHardRevocation())
        {
            // hard revocation is valid at all times
            return true;
        }

        // creation <= eval < expiration
        Date creation = getCreationTime();
        Date expiration = getExpirationTime();
        return !evaluationTime.before(creation) && (expiration == null || evaluationTime.before(expiration));
    }

    /**
     * Return true, if this signature is a hard revocation.
     * Contrary to soft revocations (the key / signature / user-id was gracefully retired), a hard revocation
     * has a serious reason, like key compromise, or no reason at all.
     * Hard revocations invalidate the key / signature / user-id retroactively, while soft revocations only
     * invalidate from the time of revocation signature creation onwards.
     *
     * @return true if the signature is a hard revocation
     */
    public boolean isHardRevocation()
    {
        return signature.isHardRevocation();
    }

    /**
     * Return true, if this signature is a certification.
     * Certification signatures are used to bind user-ids to a key.
     *
     * @return true if the signature is a certification
     */
    public boolean isCertification()
    {
        return signature.isCertification();
    }


    /**
     * Check certain requirements for OpenPGP signatures.
     *
     * @param issuer signature issuer
     * @throws MalformedPGPSignatureException if the signature is malformed
     */
    void sanitize(OpenPGPCertificate.OpenPGPComponentKey issuer)
            throws MalformedPGPSignatureException
    {
        PGPSignatureSubpacketVector hashed = signature.getHashedSubPackets();
        if (hashed == null)
        {
            throw new MalformedPGPSignatureException("Missing hashed signature subpacket area.");
        }
        PGPSignatureSubpacketVector unhashed = signature.getUnhashedSubPackets();

        if (hashed.getSignatureCreationTime() == null)
        {
            // Signatures MUST have hashed creation time subpacket
            throw new MalformedPGPSignatureException("Signature does not have a hashed SignatureCreationTime subpacket.");
        }

        if (hashed.getSignatureCreationTime().before(issuer.getCreationTime()))
        {
            throw new MalformedPGPSignatureException("Signature predates issuer key creation time.");
        }

        for (NotationData notation : hashed.getNotationDataOccurrences())
        {
            if (notation.isCritical())
            {
                throw new MalformedPGPSignatureException("Critical unknown NotationData encountered: " + notation.getNotationName());
            }
        }

        for (SignatureSubpacket unknownSubpacket : hashed.toArray())
        {
            // SignatureSubpacketInputStream returns unknown subpackets as SignatureSubpacket
            if (unknownSubpacket.isCritical() &&
                    unknownSubpacket.getClass().equals(SignatureSubpacket.class))
            {
                throw new MalformedPGPSignatureException("Critical hashed unknown SignatureSubpacket encountered: "
                        + unknownSubpacket.getType());
            }
        }

        switch (signature.getVersion())
        {
            case SignaturePacket.VERSION_4:
                if (hashed.getIssuerFingerprint() == null &&
                        unhashed.getIssuerFingerprint() == null &&
                        hashed.getSubpacket(SignatureSubpacketTags.ISSUER_KEY_ID) == null &&
                        unhashed.getSubpacket(SignatureSubpacketTags.ISSUER_KEY_ID) == null)
                {
                    throw new MalformedPGPSignatureException("Missing IssuerKeyID and IssuerFingerprint subpacket.");
                }
                break;

            case SignaturePacket.VERSION_5:
                // TODO: Implement
                break;

            case SignaturePacket.VERSION_6:
                if (hashed.getSubpacket(SignatureSubpacketTags.ISSUER_KEY_ID) != null)
                {
                    throw new MalformedPGPSignatureException("v6 signature MUST NOT contain IssuerKeyID subpacket.");
                }
                if (hashed.getIssuerFingerprint() == null && unhashed.getIssuerFingerprint() == null)
                {
                    throw new MalformedPGPSignatureException("v6 signature MUST contain IssuerFingerprint subpacket.");
                }
                break;

            default:
        }
    }

    /**
     * Return true, if this signature is a revocation, false otherwise.
     * @return true if signature is revocation
     */
    public boolean isRevocation()
    {
        return PGPSignature.isRevocation(signature.getSignatureType());
    }

    @Override
    public String toString()
    {
        String issuerInfo = getIssuerDisplay();
        String period = UTCUtil.format(getCreationTime()) +
                (getExpirationTime() == null ? "" : ">" + UTCUtil.format(getExpirationTime()));
        String validity = isTested ? (isCorrect ? "✓" : "✗") : "❓";
        // -DM Hex.toHexString
        return getType() + (signature.isHardRevocation() ? "(hard)" : "") + " " + Hex.toHexString(signature.getDigestPrefix()) +
                " " + issuerInfo + " -> " + getTargetDisplay() + " (" + period + ") " + validity;
    }

    protected String getIssuerDisplay()
    {
        if (issuer != null)
        {
            return issuer.toString();
        }

        KeyIdentifier issuerIdentifier = getKeyIdentifier();
        if (issuerIdentifier == null)
        {
            return "External[unknown]";
        }

        if (issuerIdentifier.isWildcard())
        {
            return "Anonymous";
        }
        return "External[" + Long.toHexString(issuerIdentifier.getKeyId()).toUpperCase() + "]";
    }

    protected abstract String getTargetDisplay();

    protected String getType()
    {
        switch (signature.getSignatureType())
        {
            case PGPSignature.BINARY_DOCUMENT:
                return "BINARY_DOCUMENT";
            case PGPSignature.CANONICAL_TEXT_DOCUMENT:
                return "CANONICAL_TEXT_DOCUMENT";
            case PGPSignature.STAND_ALONE:
                return "STANDALONE";
            case PGPSignature.DEFAULT_CERTIFICATION:
                return "DEFAULT_CERTIFICATION";
            case PGPSignature.NO_CERTIFICATION:
                return "NO_CERTIFICATION";
            case PGPSignature.CASUAL_CERTIFICATION:
                return "CASUAL_CERTIFICATION";
            case PGPSignature.POSITIVE_CERTIFICATION:
                return "POSITIVE_CERTIFICATION";
            case PGPSignature.SUBKEY_BINDING:
                return "SUBKEY_BINDING";
            case PGPSignature.PRIMARYKEY_BINDING:
                return "PRIMARYKEY_BINDING";
            case PGPSignature.DIRECT_KEY:
                return "DIRECT_KEY";
            case PGPSignature.KEY_REVOCATION:
                return "KEY_REVOCATION";
            case PGPSignature.SUBKEY_REVOCATION:
                return "SUBKEY_REVOCATION";
            case PGPSignature.CERTIFICATION_REVOCATION:
                return "CERTIFICATION_REVOCATION";
            case PGPSignature.TIMESTAMP:
                return "TIMESTAMP";
            case PGPSignature.THIRD_PARTY_CONFIRMATION:
                return "THIRD_PARTY_CONFIRMATION";
            default:
                return "UNKNOWN (" + signature.getSignatureType() + ")";
        }
    }

    /**
     * An {@link OpenPGPSignature} made over a binary or textual document (e.g. a message).
     * Also known as a Data Signature.
     * An {@link OpenPGPDocumentSignature} CANNOT live on a {@link OpenPGPCertificate}.
     */
    public static class OpenPGPDocumentSignature
            extends OpenPGPSignature
    {
        protected final OpenPGPDocumentSignature attestedSignature;

        /**
         * Create a document signature of level 0 (signature is made directly over the document).
         *
         * @param signature signature
         * @param issuer public issuer-signing-key-component (or null if not available)
         */
        public OpenPGPDocumentSignature(PGPSignature signature, OpenPGPCertificate.OpenPGPComponentKey issuer)
        {
            super(signature, issuer);
            this.attestedSignature = null;
        }

        @Override
        protected String getTargetDisplay()
        {
            return "<document>";
        }

        /**
         * Create a document signature of level greater than 0 (signature is made as an attestation over
         * other signature(s) + document).
         * If the attested signature is itself an attestation, it will recursively contain its attested signature.
         *
         * @param signature attestation signature
         * @param issuer public issuer signing-key-component (or null if not available)
         * @param attestedSignature the attested signature
         */
        public OpenPGPDocumentSignature(PGPSignature signature,
                                        OpenPGPCertificate.OpenPGPComponentKey issuer,
                                        OpenPGPDocumentSignature attestedSignature)
        {
            super(signature, issuer);
            this.attestedSignature = attestedSignature;
        }

        /**
         * Return the signature attestation level of this signature.
         * If this signature was created directly over a document, this method returns 0.
         * A level greater than 0 indicates that the signature is an attestation over at least one other signature.
         *
         * @return signature attestation level
         */
        public int getSignatureLevel()
        {
            if (attestedSignature == null)
            {
                return 0; // signature over data
            }
            else
            {
                return 1 + attestedSignature.getSignatureLevel();
            }
        }

        /**
         * Return the attested signature (or null if this is not an attestation signature).
         *
         * @return attested signature or null
         */
        public OpenPGPDocumentSignature getAttestedSignature()
        {
            return attestedSignature;
        }

        /**
         * Verify the correctness of an inline signature by evaluating the corresponding {@link PGPOnePassSignature}.
         *
         * @param ops one-pass-signature packet
         * @return true if the signature is correct, false otherwise
         * @throws PGPException if the signature cannot be verified
         */
        public boolean verify(PGPOnePassSignature ops)
                throws PGPException
        {
            isTested = true;
            isCorrect = ops.verify(signature);
            return isCorrect;
        }

        /**
         * Verify the correctness of a prefixed-signature.
         *
         * @return true if the signature is correct, false otherwise
         * @throws PGPException if the signature cannot be verified
         */
        public boolean verify()
                throws PGPException
        {
            isTested = true;
            isCorrect = signature.verify();
            return isCorrect;
        }

        /**
         * Return true, if the signature is valid at this moment.
         * A valid signature is effective, correct and was issued by a valid signing key.
         *
         * @return true if the signature is valid now.
         */
        public boolean isValid()
        {
            return isValidAt(getCreationTime());
        }

        /**
         * Return true, if th signature is valid at the given date.
         * A valid signature is effective, correct and was issued by a valid signing key.
         *
         * @param date evaluation time
         * @return true if the signature is valid at the given date
         * @throws IllegalStateException if the signature has not yet been tested using a <pre>verify()</pre> method.
         */
        public boolean isValidAt(Date date)
        {
            if (!isTested)
            {
                throw new IllegalStateException("Signature has not yet been verified.");
            }
            if (!isTestedCorrect())
            {
                return false;
            }
            return issuer.isSigningKey(date);
        }
    }
}
