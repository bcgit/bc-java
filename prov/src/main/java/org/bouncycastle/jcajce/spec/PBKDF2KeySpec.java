package org.bouncycastle.jcajce.spec;

import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Extension of PBEKeySpec which takes into account the PRF algorithm setting available in PKCS#5 PBKDF2.
 */
public class PBKDF2KeySpec
    extends PBEKeySpec
{
    private static final AlgorithmIdentifier defaultPRF = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1, DERNull.INSTANCE);

    private AlgorithmIdentifier prf;

    /**
     * Base constructor.
     *
     * @param password password to use as the seed of the PBE key generator.
     * @param salt salt to use in the generator,
     * @param iterationCount iteration count to use in the generator.
     * @param keySize size of the key to be generated (in bits).
     * @param prf identifier and parameters for the PRF algorithm to use.
     */
    public PBKDF2KeySpec(char[] password, byte[] salt, int iterationCount, int keySize, AlgorithmIdentifier prf)
    {
        super(password, salt, iterationCount, keySize);

        this.prf = prf;
    }

    /**
     * Return true if this spec is for the default PRF (HmacSHA1), false otherwise.
     *
     * @return true if this spec uses the default PRF, false otherwise.
     */
    public boolean isDefaultPrf()
    {
        return defaultPRF.equals(prf);
    }

    /**
     * Return an AlgorithmIdentifier representing the PRF.
     *
     * @return the PRF's AlgorithmIdentifier.
     */
    public AlgorithmIdentifier getPrf()
    {
        return prf;
    }
}
