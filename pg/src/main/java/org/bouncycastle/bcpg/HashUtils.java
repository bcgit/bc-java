package org.bouncycastle.bcpg;

public class HashUtils
{

    /**
     * Return the length of the salt per hash algorithm, used in OpenPGP v6 signatures.
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#hash-algorithms-registry">
     *     Salt Size declarations</a>
     * @param hashAlgorithm hash algorithm tag
     * @return size of the salt for the given hash algorithm in bytes
     */
    public static int getV6SignatureSaltSizeInBytes(int hashAlgorithm)
    {
        switch (hashAlgorithm)
        {
            case HashAlgorithmTags.SHA256:
            case HashAlgorithmTags.SHA224:
            case HashAlgorithmTags.SHA3_256:
            case HashAlgorithmTags.SHA3_256_OLD:
                return 16;
            case HashAlgorithmTags.SHA384:
                return 24;
            case HashAlgorithmTags.SHA512:
            case HashAlgorithmTags.SHA3_512:
            case HashAlgorithmTags.SHA3_512_OLD:
                return 32;
            default:
                throw new IllegalArgumentException("Salt size not specified for Hash Algorithm with ID " + hashAlgorithm);
        }
    }

    /**
     * Return true, if the encountered saltLength matches the value the specification gives for the hashAlgorithm.
     *
     * @param hashAlgorithm hash algorithm tag
     * @param saltSize encountered salt size
     * @return true if the encountered size matches the spec
     * @implNote LibrePGP allows for zero-length signature salt values, so this method only works for IETF OpenPGP v6.
     */
    public boolean saltSizeMatchesSpec(int hashAlgorithm, int saltSize)
    {
        try
        {
            return saltSize == getV6SignatureSaltSizeInBytes(hashAlgorithm);
        }
        catch (IllegalArgumentException e) // Unknown algorithm or salt size is not specified for the hash algo
        {
            return false;
        }
    }
}
