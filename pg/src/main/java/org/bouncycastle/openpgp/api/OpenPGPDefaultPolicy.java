package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.api.util.UTCUtil;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class OpenPGPDefaultPolicy
        implements OpenPGPPolicy
{
    private final Map<Integer, Date> hashAlgorithmCutoffDates = new HashMap<>();
    private final Map<Integer, Date> symmetricKeyAlgorithmCutoffDates = new HashMap<>();
    private final Map<Integer, Integer> publicKeyMinimalBitStrengths = new HashMap<>();

    public OpenPGPDefaultPolicy()
    {
        /*
         * Hash Algorithms
         */
        // SHA-3
        acceptHashAlgorithm(HashAlgorithmTags.SHA3_512);
        acceptHashAlgorithm(HashAlgorithmTags.SHA3_256);
        // SHA-2
        acceptHashAlgorithm(HashAlgorithmTags.SHA512);
        acceptHashAlgorithm(HashAlgorithmTags.SHA384);
        acceptHashAlgorithm(HashAlgorithmTags.SHA256);
        acceptHashAlgorithm(HashAlgorithmTags.SHA224);
        // SHA-1
        acceptHashAlgorithmUntil(HashAlgorithmTags.SHA1, UTCUtil.parse("2023-02-01 00:00:00 UTC"));

        acceptHashAlgorithmUntil(HashAlgorithmTags.RIPEMD160, UTCUtil.parse("2023-02-01 00:00:00 UTC"));
        acceptHashAlgorithmUntil(HashAlgorithmTags.MD5, UTCUtil.parse("1997-02-01 00:00:00 UTC"));

        /*
         * Symmetric Key Algorithms
         */
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

        acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, 2000);
        acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.ELGAMAL_GENERAL, 2000);

        acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.DSA, 2000);
        acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.ECDSA, 250);
        acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.EDDSA_LEGACY, 250);
        acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.DIFFIE_HELLMAN, 2000);
        acceptPublicKeyAlgorithmWithMinimalStrength(PublicKeyAlgorithmTags.ECDH, 250);

        acceptPublicKeyAlgorithm(PublicKeyAlgorithmTags.X25519);
        acceptPublicKeyAlgorithm(PublicKeyAlgorithmTags.X448);
        acceptPublicKeyAlgorithm(PublicKeyAlgorithmTags.Ed25519);
        acceptPublicKeyAlgorithm(PublicKeyAlgorithmTags.Ed448);
    }

    public OpenPGPDefaultPolicy rejectHashAlgorithm(int hashAlgorithmId)
    {
        hashAlgorithmCutoffDates.remove(hashAlgorithmId);
        return this;
    }

    public OpenPGPDefaultPolicy acceptHashAlgorithm(int hashAlgorithmId)
    {
        return acceptHashAlgorithmUntil(hashAlgorithmId, null);
    }

    public OpenPGPDefaultPolicy acceptHashAlgorithmUntil(int hashAlgorithmId, Date until)
    {
        hashAlgorithmCutoffDates.put(hashAlgorithmId, until);
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
        return isAcceptable(hashAlgorithmId, signatureCreationTime, hashAlgorithmCutoffDates);
    }

    @Override
    public boolean isAcceptableRevocationSignatureHashAlgorithm(int hashAlgorithmId, Date signatureCreationTime)
    {
        return isAcceptable(hashAlgorithmId, signatureCreationTime, hashAlgorithmCutoffDates);
    }

    @Override
    public boolean isAcceptableCertificationSignatureHashAlgorithm(int hashAlgorithmId, Date signatureCreationTime)
    {
        return isAcceptable(hashAlgorithmId, signatureCreationTime, hashAlgorithmCutoffDates);
    }

    @Override
    public boolean isAcceptableSymmetricKeyAlgorithm(int symmetricKeyAlgorithmId)
    {
        return isAcceptable(symmetricKeyAlgorithmId, symmetricKeyAlgorithmCutoffDates);
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
