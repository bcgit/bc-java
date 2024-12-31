package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public interface OpenPGPPolicy
{
    default boolean isAcceptableSigningKey(PGPPublicKey key)
    {
        return isAcceptablePublicKey(key);
    }

    default boolean isAcceptableVerificationKey(PGPPublicKey key)
    {
        return isAcceptablePublicKey(key);
    }

    default boolean isAcceptableEncryptionKey(PGPPublicKey key)
    {
        return isAcceptablePublicKey(key);
    }

    default boolean isAcceptableDecryptionKey(PGPPublicKey key)
    {
        return isAcceptablePublicKey(key);
    }

    default boolean isAcceptablePublicKey(PGPPublicKey key)
    {
        switch (key.getVersion())
        {
            case PublicKeyPacket.VERSION_4:
            case PublicKeyPacket.LIBREPGP_5:
            case PublicKeyPacket.VERSION_6:
                switch (key.getAlgorithm())
                {
                    case PublicKeyAlgorithmTags.RSA_GENERAL:
                    case PublicKeyAlgorithmTags.Ed25519:
                    case PublicKeyAlgorithmTags.Ed448:
                    case PublicKeyAlgorithmTags.X25519:
                    case PublicKeyAlgorithmTags.X448:
                        return isAcceptablePublicKeyStrength(key.getAlgorithm(), key.getBitStrength());

                    default:
                        return false;
                }

            default:
                return false;
        }
    }

    default boolean isAcceptableSignature(PGPSignature signature)
    {
        return hasAcceptableSignatureHashAlgorithm(signature) &&
                hasNoCriticalUnknownNotations(signature) &&
                hasNoCriticalUnknownSubpackets(signature);
    }

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

    default boolean hasAcceptableDocumentSignatureHashAlgorithm(PGPSignature signature)
    {
        return isAcceptableDocumentSignatureHashAlgorithm(signature.getHashAlgorithm(), signature.getCreationTime());
    }

    default boolean hasAcceptableRevocationSignatureHashAlgorithm(PGPSignature signature)
    {
        return isAcceptableRevocationSignatureHashAlgorithm(signature.getHashAlgorithm(), signature.getCreationTime());
    }

    default boolean hasAcceptableCertificationSignatureHashAlgorithm(PGPSignature signature)
    {
        return isAcceptableCertificationSignatureHashAlgorithm(signature.getHashAlgorithm(), signature.getCreationTime());
    }

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

    default boolean isKnownSignatureSubpacket(int signatureSubpacketTag)
    {
        return false;
    }

    boolean isAcceptableDocumentSignatureHashAlgorithm(int hashAlgorithmId, Date signatureCreationTime);

    boolean isAcceptableRevocationSignatureHashAlgorithm(int hashAlgorithmId, Date signatureCreationTime);

    boolean isAcceptableCertificationSignatureHashAlgorithm(int hashAlgorithmId, Date signatureCreationTime);

    boolean isAcceptableSymmetricKeyAlgorithm(int symmetricKeyAlgorithmId);

    boolean isAcceptablePublicKeyStrength(int publicKeyAlgorithmId, int bitStrength);

    OpenPGPNotationRegistry getNotationRegistry();

    class OpenPGPNotationRegistry
    {
        private final Set<String> knownNotations = new HashSet<>();

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
