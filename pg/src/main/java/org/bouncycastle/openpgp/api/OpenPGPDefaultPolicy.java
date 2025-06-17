package org.bouncycastle.openpgp.api;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
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
