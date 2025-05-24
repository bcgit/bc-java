package org.bouncycastle.openpgp.api;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;

/**
 * Policy for OpenPGP algorithms and features.
 */
public interface OpenPGPPolicy
{
    /**
     * Return true, if the given {@link PGPPublicKey} is an acceptable signing key.
     * Note: Although signing requires a secret key, we perform checks on the public part for consistency.
     *
     * @param key key
     * @return true if acceptable signing key
     */
    default boolean isAcceptableSigningKey(PGPPublicKey key)
    {
        return isAcceptablePublicKey(key);
    }

    /**
     * Return true, if the given {@link PGPPublicKey} is an acceptable signature verification key.
     * Note: The asymmetry between this and {@link #isAcceptableSigningKey(PGPPublicKey)} is useful
     * to prevent creation of signatures using a legacy key, while still allowing verification of
     * signatures made using the same key.
     *
     * @param key key
     * @return true if acceptable verification key
     */
    default boolean isAcceptableVerificationKey(PGPPublicKey key)
    {
        return isAcceptablePublicKey(key);
    }

    /**
     * Return true, if the given {@link PGPPublicKey} is acceptable for encrypting messages.
     *
     * @param key key
     * @return true if acceptable encryption key
     */
    default boolean isAcceptableEncryptionKey(PGPPublicKey key)
    {
        return isAcceptablePublicKey(key);
    }

    /**
     * Return true, if the given {@link PGPPublicKey} is acceptable for decrypting messages.
     * Note: Although decryption requires a secret key, we perform checks on the public part for consistency.
     * The asymmetry between this and {@link #isAcceptableEncryptionKey(PGPPublicKey)} is useful
     * to prevent creation of new encrypted messages using a legacy key, while still allowing decryption
     * of existing messages using the same key.
     *
     * @param key key
     * @return true if acceptable decryption key
     */
    default boolean isAcceptableDecryptionKey(PGPPublicKey key)
    {
        return isAcceptablePublicKey(key);
    }

    /**
     * Return true, if the given {@link PGPPublicKey} is acceptable.
     *
     * @param key key
     * @return true if acceptable key
     */
    default boolean isAcceptablePublicKey(PGPPublicKey key)
    {
        return isAcceptablePublicKeyStrength(key.getAlgorithm(), key.getBitStrength());
    }

    /**
     * Return true, if the given {@link PGPSignature} is acceptable (uses acceptable hash algorithm,
     * does not contain unknown critical notations or subpackets).
     * Note: A signature being acceptable does NOT mean that it is correct or valid.
     *
     * @param signature signature
     * @return true if acceptable
     */
    default boolean isAcceptableSignature(PGPSignature signature)
    {
        return hasAcceptableSignatureHashAlgorithm(signature) &&
                hasNoCriticalUnknownNotations(signature) &&
                hasNoCriticalUnknownSubpackets(signature);
    }

    /**
     * Return true, if the given {@link PGPSignature} was made using an acceptable signature hash algorithm.
     *
     * @param signature signature
     * @return true if hash algorithm is acceptable
     */
    default boolean hasAcceptableSignatureHashAlgorithm(PGPSignature signature)
    {
        switch (signature.getSignatureType())
        {
            case PGPSignature.DEFAULT_CERTIFICATION:
            case PGPSignature.NO_CERTIFICATION:
            case PGPSignature.CASUAL_CERTIFICATION:
            case PGPSignature.POSITIVE_CERTIFICATION:
            case PGPSignature.DIRECT_KEY:
            case PGPSignature.SUBKEY_BINDING:
            case PGPSignature.PRIMARYKEY_BINDING:
                return hasAcceptableCertificationSignatureHashAlgorithm(signature);

            case PGPSignature.CERTIFICATION_REVOCATION:
            case PGPSignature.KEY_REVOCATION:
            case PGPSignature.SUBKEY_REVOCATION:
                return hasAcceptableRevocationSignatureHashAlgorithm(signature);

            case PGPSignature.BINARY_DOCUMENT:
            case PGPSignature.CANONICAL_TEXT_DOCUMENT:
            default:
                return hasAcceptableDocumentSignatureHashAlgorithm(signature);
        }
    }

    /**
     * Return true, if the {@link PGPSignature} uses an acceptable data/document signature hash algorithm.
     *
     * @param signature data / document signature
     * @return true if hash algorithm is acceptable
     */
    default boolean hasAcceptableDocumentSignatureHashAlgorithm(PGPSignature signature)
    {
        return isAcceptableDocumentSignatureHashAlgorithm(signature.getHashAlgorithm(), signature.getCreationTime());
    }

    /**
     * Return true, if the {@link PGPSignature} uses an acceptable revocation signature hash algorithm.
     *
     * @param signature revocation signature
     * @return true if hash algorithm is acceptable
     */
    default boolean hasAcceptableRevocationSignatureHashAlgorithm(PGPSignature signature)
    {
        return isAcceptableRevocationSignatureHashAlgorithm(signature.getHashAlgorithm(), signature.getCreationTime());
    }

    /**
     * Return true, if the {@link PGPSignature} uses an acceptable certification signature hash algorithm.
     *
     * @param signature certification signature
     * @return true if hash algorithm is acceptable
     */
    default boolean hasAcceptableCertificationSignatureHashAlgorithm(PGPSignature signature)
    {
        return isAcceptableCertificationSignatureHashAlgorithm(signature.getHashAlgorithm(), signature.getCreationTime());
    }

    /**
     * Return true, if the hashed subpacket area of the signature does NOT contain unknown critical notations.
     * @param signature signature
     * @return true if signature is free from unknown critical notations
     */
    default boolean hasNoCriticalUnknownNotations(PGPSignature signature)
    {
        PGPSignatureSubpacketVector hashedSubpackets = signature.getHashedSubPackets();
        if (hashedSubpackets == null)
        {
            return true;
        }

        OpenPGPNotationRegistry registry = getNotationRegistry();

        NotationData[] notations = hashedSubpackets.getNotationDataOccurrences();
        for (NotationData notation : notations)
        {
            if (notation.isCritical() && !registry.isNotationKnown(notation.getNotationName()))
            {
                return false;
            }
        }
        return true;
    }

    /**
     * Return true, if the hashed subpacket area of the signature does NOT contain unknown critical subpackets.
     * @param signature signature
     * @return true if signature is free from unknown critical subpackets
     */
    default boolean hasNoCriticalUnknownSubpackets(PGPSignature signature)
    {
        PGPSignatureSubpacketVector hashedSubpackets = signature.getHashedSubPackets();
        if (hashedSubpackets == null)
        {
            return true;
        }

        for (SignatureSubpacket subpacket : hashedSubpackets.toArray())
        {
            if (subpacket.isCritical() &&
                    // only consider subpackets which are not recognized by SignatureSubpacketInputStream
                    subpacket.getClass().equals(SignatureSubpacket.class))
            {
                if (!isKnownSignatureSubpacket(subpacket.getType()))
                {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Return true, if the given signature subpacket ID is known by the implementation.
     * Note: This method is only called for subpackets not recognized by
     * {@link org.bouncycastle.bcpg.SignatureSubpacketInputStream}.
     *
     * @param signatureSubpacketTag signature subpacket ID
     * @return true if subpacket tag is known
     */
    default boolean isKnownSignatureSubpacket(int signatureSubpacketTag)
    {
        // Overwrite this, allowing custom critical signature subpackets
        return false;
    }

    /**
     * Return true, if the given hash algorithm is - at signature creation time - an acceptable document signature
     * hash algorithm.
     *
     * @param hashAlgorithmId hash algorithm ID
     * @param signatureCreationTime optional signature creation time
     * @return true if hash algorithm is acceptable at creation time
     */
    boolean isAcceptableDocumentSignatureHashAlgorithm(int hashAlgorithmId, Date signatureCreationTime);

    /**
     * Return true, if the given hash algorithm is - at signature creation time - an acceptable revocation signature
     * hash algorithm.
     *
     * @param hashAlgorithmId hash algorithm ID
     * @param signatureCreationTime optional signature creation time
     * @return true if hash algorithm is acceptable at creation time
     */
    boolean isAcceptableRevocationSignatureHashAlgorithm(int hashAlgorithmId, Date signatureCreationTime);

    /**
     * Return true, if the given hash algorithm is - at signature creation time - an acceptable certification signature
     * hash algorithm.
     *
     * @param hashAlgorithmId hash algorithm ID
     * @param signatureCreationTime optional signature creation time
     * @return true if hash algorithm is acceptable at creation time
     */
    boolean isAcceptableCertificationSignatureHashAlgorithm(int hashAlgorithmId, Date signatureCreationTime);

    /**
     * Return the default certification signature hash algorithm ID.
     * This is used as fallback, if negotiation of a commonly supported hash algorithm fails.
     *
     * @return default certification signature hash algorithm ID
     */
    int getDefaultCertificationSignatureHashAlgorithm();

    /**
     * Return the default document signature hash algorithm ID.
     * This is used as fallback, if negotiation of a commonly supported hash algorithm fails.
     *
     * @return default document signature hash algorithm ID
     */
    int getDefaultDocumentSignatureHashAlgorithm();

    /**
     * Return true, if the given symmetric-key algorithm is acceptable.
     *
     * @param symmetricKeyAlgorithmId symmetric-key algorithm
     * @return true if symmetric-key algorithm is acceptable
     */
    boolean isAcceptableSymmetricKeyAlgorithm(int symmetricKeyAlgorithmId);

    /**
     * Return the default symmetric-key algorithm, which is used as a fallback if symmetric encryption algorithm
     * negotiation fails.
     *
     * @return default symmetric-key algorithm
     */
    int getDefaultSymmetricKeyAlgorithm();

    /**
     * Return true, if the given bitStrength is acceptable for the given public key algorithm ID.
     *
     * @param publicKeyAlgorithmId ID of a public key algorithm
     * @param bitStrength key bit strength
     * @return true if strength is acceptable
     */
    boolean isAcceptablePublicKeyStrength(int publicKeyAlgorithmId, int bitStrength);

    /**
     * Return the policies {@link OpenPGPNotationRegistry} containing known notation names.
     *
     * @return notation registry
     */
    OpenPGPNotationRegistry getNotationRegistry();

    /**
     * The {@link OpenPGPNotationRegistry} can be used to register known notations, such that signatures containing
     * notation instances of the same name, which are marked as critical do not invalidate the signature.
     */
    class OpenPGPNotationRegistry
    {
        private final Set<String> knownNotations = new HashSet<String>();

        public boolean isNotationKnown(String notationName)
        {
            return knownNotations.contains(notationName);
        }

        public void addKnownNotation(String notationName)
        {
            this.knownNotations.add(notationName);
        }
    }
}
