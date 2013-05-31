package org.bouncycastle.pqc.jcajce.spec;

import org.bouncycastle.pqc.crypto.gmss.GMSSParameters;

/**
 * This class provides a specification for a GMSS public key.
 *
 * @see org.bouncycastle.pqc.jcajce.provider.gmss.BCGMSSPublicKey
 */
public class GMSSPublicKeySpec
    extends GMSSKeySpec
{
    /**
     * The GMSS public key
     */
    private byte[] gmssPublicKey;

    /**
     * The constructor.
     *
     * @param key              a raw GMSS public key
     * @param gmssParameterSet an instance of GMSSParameterSet
     */
    public GMSSPublicKeySpec(byte[] key, GMSSParameters gmssParameterSet)
    {
        super(gmssParameterSet);

        this.gmssPublicKey = key;
    }

    /**
     * Returns the GMSS public key
     *
     * @return The GMSS public key
     */
    public byte[] getPublicKey()
    {
        return gmssPublicKey;
    }
}
