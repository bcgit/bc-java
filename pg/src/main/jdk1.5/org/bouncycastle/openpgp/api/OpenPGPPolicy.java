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
    boolean isAcceptableSigningKey(PGPPublicKey key);

    /**
     * Return true, if the given {@link PGPPublicKey} is an acceptable signature verification key.
     * Note: The asymmetry between this and {@link #isAcceptableSigningKey(PGPPublicKey)} is useful
     * to prevent creation of signatures using a legacy key, while still allowing verification of
     * signatures made using the same key.
     *
     * @param key key
     * @return true if acceptable verification key
     */
    boolean isAcceptableVerificationKey(PGPPublicKey key);

    /**
     * Return true, if the given {@link PGPPublicKey} is acceptable for encrypting messages.
     *
     * @param key key
     * @return true if acceptable encryption key
     */
    boolean isAcceptableEncryptionKey(PGPPublicKey key);

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
    boolean isAcceptableDecryptionKey(PGPPublicKey key);

    /**
     * Return true, if the given {@link PGPPublicKey} is acceptable.
     *
     * @param key key
     * @return true if acceptable key
     */
    boolean isAcceptablePublicKey(PGPPublicKey key);

    /**
     * Return true, if the given {@link PGPSignature} is acceptable (uses acceptable hash algorithm,
     * does not contain unknown critical notations or subpackets).
     * Note: A signature being acceptable does NOT mean that it is correct or valid.
     *
     * @param signature signature
     * @return true if acceptable
     */
    boolean isAcceptableSignature(PGPSignature signature);

    /**
     * Return true, if the given {@link PGPSignature} was made using an acceptable signature hash algorithm.
     *
     * @param signature signature
     * @return true if hash algorithm is acceptable
     */
    boolean hasAcceptableSignatureHashAlgorithm(PGPSignature signature);

    /**
     * Return true, if the {@link PGPSignature} uses an acceptable data/document signature hash algorithm.
     *
     * @param signature data / document signature
     * @return true if hash algorithm is acceptable
     */
    boolean hasAcceptableDocumentSignatureHashAlgorithm(PGPSignature signature);

    /**
     * Return true, if the {@link PGPSignature} uses an acceptable revocation signature hash algorithm.
     *
     * @param signature revocation signature
     * @return true if hash algorithm is acceptable
     */
    boolean hasAcceptableRevocationSignatureHashAlgorithm(PGPSignature signature);

    /**
     * Return true, if the {@link PGPSignature} uses an acceptable certification signature hash algorithm.
     *
     * @param signature certification signature
     * @return true if hash algorithm is acceptable
     */
    boolean hasAcceptableCertificationSignatureHashAlgorithm(PGPSignature signature);

    /**
     * Return true, if the hashed subpacket area of the signature does NOT contain unknown critical notations.
     * @param signature signature
     * @return true if signature is free from unknown critical notations
     */
    boolean hasNoCriticalUnknownNotations(PGPSignature signature);

    /**
     * Return true, if the hashed subpacket area of the signature does NOT contain unknown critical subpackets.
     * @param signature signature
     * @return true if signature is free from unknown critical subpackets
     */
    boolean hasNoCriticalUnknownSubpackets(PGPSignature signature);

    /**
     * Return true, if the given signature subpacket ID is known by the implementation.
     * Note: This method is only called for subpackets not recognized by
     * {@link org.bouncycastle.bcpg.SignatureSubpacketInputStream}.
     *
     * @param signatureSubpacketTag signature subpacket ID
     * @return true if subpacket tag is known
     */
    boolean isKnownSignatureSubpacket(int signatureSubpacketTag);

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
