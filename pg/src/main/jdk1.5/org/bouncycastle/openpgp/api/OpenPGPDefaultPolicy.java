package org.bouncycastle.openpgp.api;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.api.util.UTCUtil;

public class OpenPGPDefaultPolicy
        implements OpenPGPPolicy
{
    private final Map<Integer, Date> documentHashAlgorithmCutoffDates = new HashMap<Integer, Date>();
    private final Map<Integer, Date> certificateHashAlgorithmCutoffDates = new HashMap<Integer, Date>();
    private final Map<Integer, Date> symmetricKeyAlgorithmCutoffDates = new HashMap<Integer, Date>();
    private final Map<Integer, Integer> publicKeyMinimalBitStrengths = new HashMap<Integer, Integer>();
    private int defaultDocumentSignatureHashAlgorithm = HashAlgorithmTags.SHA512;
    private int defaultCertificationSignatureHashAlgorithm = HashAlgorithmTags.SHA512;
    private int defaultSymmetricKeyAlgorithm = SymmetricKeyAlgorithmTags.AES_128;

    public OpenPGPDefaultPolicy()
    {
        /*
         * Certification Signature Hash Algorithms
         */
        setDefaultCertificationSignatureHashAlgorithm(HashAlgorithmTags.SHA512);
        // SHA-3
        acceptCertificationSignatureHashAlgorithm(HashAlgorithmTags.SHA3_512);
        acceptCertificationSignatureHashAlgorithm(HashAlgorithmTags.SHA3_256);
        // SHA-2
        acceptCertificationSignatureHashAlgorithm(HashAlgorithmTags.SHA512);
        acceptCertificationSignatureHashAlgorithm(HashAlgorithmTags.SHA384);
        acceptCertificationSignatureHashAlgorithm(HashAlgorithmTags.SHA256);
        acceptCertificationSignatureHashAlgorithm(HashAlgorithmTags.SHA224);
        // SHA-1
        acceptCertificationSignatureHashAlgorithmUntil(HashAlgorithmTags.SHA1, UTCUtil.parse("2023-02-01 00:00:00 UTC"));

        acceptCertificationSignatureHashAlgorithmUntil(HashAlgorithmTags.RIPEMD160, UTCUtil.parse("2023-02-01 00:00:00 UTC"));
        acceptCertificationSignatureHashAlgorithmUntil(HashAlgorithmTags.MD5, UTCUtil.parse("1997-02-01 00:00:00 UTC"));

        /*
         * Document Signature Hash Algorithms
         */
        setDefaultDocumentSignatureHashAlgorithm(HashAlgorithmTags.SHA512);
        // SHA-3
        acceptDocumentSignatureHashAlgorithm(HashAlgorithmTags.SHA3_512);
        acceptDocumentSignatureHashAlgorithm(HashAlgorithmTags.SHA3_256);
        // SHA-2
        acceptDocumentSignatureHashAlgorithm(HashAlgorithmTags.SHA512);
        acceptDocumentSignatureHashAlgorithm(HashAlgorithmTags.SHA384);
        acceptDocumentSignatureHashAlgorithm(HashAlgorithmTags.SHA256);
        acceptDocumentSignatureHashAlgorithm(HashAlgorithmTags.SHA224);

        /*
         * Symmetric Key Algorithms
         */
        setDefaultSymmetricKeyAlgorithm(SymmetricKeyAlgorithmTags.AES_128);
        acceptSymmetricKeyAlgorithm(SymmetricKeyAlgorithmTags.AES_256);
        acceptSymmetricKeyAlgorithm(SymmetricKeyAlgorithmTags.AES_192);
        acceptSymmetricKeyAlgorithm(SymmetricKeyAlgorithmTags.AES_128);
        acceptSymmetricKeyAlgorithm(SymmetricKeyAlgorithmTags.TWOFISH);
        acceptSymmetricKeyAlgorithm(SymmetricKeyAlgorithmTags.CAMELLIA_256);
        acceptSymmetricKeyAlgorithm(SymmetricKeyAlgorithmTags.CAMELLIA_192);
        acceptSymmetricKeyAlgorithm(SymmetricKeyAlgorithmTags.CAMELLIA_128);

        /*
         * Public Key Algorithms and key strengths
         */
        acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.RSA_GENERAL, 2000);
        acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.RSA_ENCRYPT, 2000);
        acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.RSA_SIGN, 2000);

        acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.ECDSA, 250);
        acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.EDDSA_LEGACY, 250);
        acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.ECDH, 250);

        acceptPublicKeyAlgorithm(PublicKeyAlgorithmTags.X25519);
        acceptPublicKeyAlgorithm(PublicKeyAlgorithmTags.X448);
        acceptPublicKeyAlgorithm(PublicKeyAlgorithmTags.Ed25519);
        acceptPublicKeyAlgorithm(PublicKeyAlgorithmTags.Ed448);
    }

    /**
     * Return true, if the given {@link PGPPublicKey} is an acceptable signing key.
     * Note: Although signing requires a secret key, we perform checks on the public part for consistency.
     *
     * @param key key
     * @return true if acceptable signing key
     */
    public boolean isAcceptableSigningKey(PGPPublicKey key)
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
    public boolean isAcceptableVerificationKey(PGPPublicKey key)
    {
        return isAcceptablePublicKey(key);
    }

    /**
     * Return true, if the given {@link PGPPublicKey} is acceptable for encrypting messages.
     *
     * @param key key
     * @return true if acceptable encryption key
     */
    public boolean isAcceptableEncryptionKey(PGPPublicKey key)
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
    public boolean isAcceptableDecryptionKey(PGPPublicKey key)
    {
        return isAcceptablePublicKey(key);
    }

    /**
     * Return true, if the given {@link PGPPublicKey} is acceptable.
     *
     * @param key key
     * @return true if acceptable key
     */
    public boolean isAcceptablePublicKey(PGPPublicKey key)
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
    public boolean isAcceptableSignature(PGPSignature signature)
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
    public boolean hasAcceptableSignatureHashAlgorithm(PGPSignature signature)
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
    public boolean hasAcceptableDocumentSignatureHashAlgorithm(PGPSignature signature)
    {
        return isAcceptableDocumentSignatureHashAlgorithm(signature.getHashAlgorithm(), signature.getCreationTime());
    }

    /**
     * Return true, if the {@link PGPSignature} uses an acceptable revocation signature hash algorithm.
     *
     * @param signature revocation signature
     * @return true if hash algorithm is acceptable
     */
    public boolean hasAcceptableRevocationSignatureHashAlgorithm(PGPSignature signature)
    {
        return isAcceptableRevocationSignatureHashAlgorithm(signature.getHashAlgorithm(), signature.getCreationTime());
    }

    /**
     * Return true, if the {@link PGPSignature} uses an acceptable certification signature hash algorithm.
     *
     * @param signature certification signature
     * @return true if hash algorithm is acceptable
     */
    public boolean hasAcceptableCertificationSignatureHashAlgorithm(PGPSignature signature)
    {
        return isAcceptableCertificationSignatureHashAlgorithm(signature.getHashAlgorithm(), signature.getCreationTime());
    }

    /**
     * Return true, if the hashed subpacket area of the signature does NOT contain unknown critical notations.
     *
     * @param signature signature
     * @return true if signature is free from unknown critical notations
     */
    public boolean hasNoCriticalUnknownNotations(PGPSignature signature)
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
     *
     * @param signature signature
     * @return true if signature is free from unknown critical subpackets
     */
    public boolean hasNoCriticalUnknownSubpackets(PGPSignature signature)
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
    public boolean isKnownSignatureSubpacket(int signatureSubpacketTag)
    {
        // Overwrite this, allowing custom critical signature subpackets
        return false;
    }

    public OpenPGPDefaultPolicy rejectHashAlgorithm(int hashAlgorithmId)
    {
        certificateHashAlgorithmCutoffDates.remove(hashAlgorithmId);
        documentHashAlgorithmCutoffDates.remove(hashAlgorithmId);
        return this;
    }

    public OpenPGPDefaultPolicy acceptCertificationSignatureHashAlgorithm(int hashAlgorithmId)
    {
        return acceptCertificationSignatureHashAlgorithmUntil(hashAlgorithmId, null);
    }

    public OpenPGPDefaultPolicy acceptCertificationSignatureHashAlgorithmUntil(int hashAlgorithmId, Date until)
    {
        certificateHashAlgorithmCutoffDates.put(hashAlgorithmId, until);
        return this;
    }

    public OpenPGPDefaultPolicy acceptDocumentSignatureHashAlgorithm(int hashAlgorithmId)
    {
        return acceptDocumentSignatureHashAlgorithmUntil(hashAlgorithmId, null);
    }

    public OpenPGPDefaultPolicy acceptDocumentSignatureHashAlgorithmUntil(int hashAlgorithmId, Date until)
    {
        documentHashAlgorithmCutoffDates.put(hashAlgorithmId, until);
        return this;
    }

    public OpenPGPDefaultPolicy rejectSymmetricKeyAlgorithm(int symmetricKeyAlgorithmId)
    {
        symmetricKeyAlgorithmCutoffDates.remove(symmetricKeyAlgorithmId);
        return this;
    }

    public OpenPGPDefaultPolicy acceptSymmetricKeyAlgorithm(int symmetricKeyAlgorithmId)
    {
        return acceptSymmetricKeyAlgorithmUntil(symmetricKeyAlgorithmId, null);
    }

    public OpenPGPDefaultPolicy acceptSymmetricKeyAlgorithmUntil(int symmetricKeyAlgorithmId, Date until)
    {
        symmetricKeyAlgorithmCutoffDates.put(symmetricKeyAlgorithmId, until);
        return this;
    }

    public OpenPGPDefaultPolicy rejectPublicKeyAlgorithm(int publicKeyAlgorithmId)
    {
        publicKeyMinimalBitStrengths.remove(publicKeyAlgorithmId);
        return this;
    }

    public OpenPGPDefaultPolicy acceptPublicKeyAlgorithm(int publicKeyAlgorithmId)
    {
        publicKeyMinimalBitStrengths.put(publicKeyAlgorithmId, null);
        return this;
    }

    public OpenPGPDefaultPolicy acceptPublicKeyAlgorithmWithMinimalStrength(int publicKeyAlgorithmId, int minBitStrength)
    {
        publicKeyMinimalBitStrengths.put(publicKeyAlgorithmId, minBitStrength);
        return this;
    }

    @Override
    public boolean isAcceptableDocumentSignatureHashAlgorithm(int hashAlgorithmId, Date signatureCreationTime)
    {
        return isAcceptable(hashAlgorithmId, signatureCreationTime, documentHashAlgorithmCutoffDates);
    }

    @Override
    public boolean isAcceptableRevocationSignatureHashAlgorithm(int hashAlgorithmId, Date signatureCreationTime)
    {
        return isAcceptable(hashAlgorithmId, signatureCreationTime, certificateHashAlgorithmCutoffDates);
    }

    @Override
    public boolean isAcceptableCertificationSignatureHashAlgorithm(int hashAlgorithmId, Date signatureCreationTime)
    {
        return isAcceptable(hashAlgorithmId, signatureCreationTime, certificateHashAlgorithmCutoffDates);
    }

    @Override
    public int getDefaultCertificationSignatureHashAlgorithm()
    {
        return defaultCertificationSignatureHashAlgorithm;
    }

    public OpenPGPDefaultPolicy setDefaultCertificationSignatureHashAlgorithm(int hashAlgorithmId)
    {
        defaultCertificationSignatureHashAlgorithm = hashAlgorithmId;
        return this;
    }

    @Override
    public int getDefaultDocumentSignatureHashAlgorithm()
    {
        return defaultDocumentSignatureHashAlgorithm;
    }

    public OpenPGPDefaultPolicy setDefaultDocumentSignatureHashAlgorithm(int hashAlgorithmId)
    {
        defaultDocumentSignatureHashAlgorithm = hashAlgorithmId;
        return this;
    }

    @Override
    public boolean isAcceptableSymmetricKeyAlgorithm(int symmetricKeyAlgorithmId)
    {
        return isAcceptable(symmetricKeyAlgorithmId, symmetricKeyAlgorithmCutoffDates);
    }

    @Override
    public int getDefaultSymmetricKeyAlgorithm()
    {
        return defaultSymmetricKeyAlgorithm;
    }

    public OpenPGPDefaultPolicy setDefaultSymmetricKeyAlgorithm(int symmetricKeyAlgorithmId)
    {
        defaultSymmetricKeyAlgorithm = symmetricKeyAlgorithmId;
        return this;
    }

    @Override
    public boolean isAcceptablePublicKeyStrength(int publicKeyAlgorithmId, int bitStrength)
    {
        return isAcceptable(publicKeyAlgorithmId, bitStrength, publicKeyMinimalBitStrengths);
    }

    @Override
    public OpenPGPNotationRegistry getNotationRegistry()
    {
        return null;
    }

    private boolean isAcceptable(int algorithmId, Date usageDate, Map<Integer, Date> cutoffTable)
    {
        if (!cutoffTable.containsKey(algorithmId))
        {
            // algorithm is not listed in the map at all
            return false;
        }

        Date cutoffDate = cutoffTable.get(algorithmId);
        if (cutoffDate == null)
        {
            // no cutoff date given -> algorithm is acceptable indefinitely
            return true;
        }

        return usageDate.before(cutoffDate);
    }

    private boolean isAcceptable(int algorithmId, Map<Integer, Date> cutoffTable)
    {
        return cutoffTable.containsKey(algorithmId);
    }

    private boolean isAcceptable(int algorithmId, int bitStrength, Map<Integer, Integer> minBitStrengths)
    {
        if (!minBitStrengths.containsKey(algorithmId))
        {
            // algorithm is not listed in the map at all
            return false;
        }

        Integer minBitStrength = minBitStrengths.get(algorithmId);
        if (minBitStrength == null)
        {
            // no minimal bit strength defined -> accept all strengths
            return true;
        }

        return bitStrength >= minBitStrength;
    }
}
