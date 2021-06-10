package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.Blake3Digest;
import org.bouncycastle.crypto.params.Blake3Parameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Bouncy implementation of Blake3Mac.
 */
public class Blake3Mac
    implements Mac
{
    /**
     * Digest.
     */
    private final Blake3Digest theDigest;

    /**
     * Create a blake3Mac with the specified digest.
     *
     * @param pDigest the base digest.
     */
    public Blake3Mac(final Blake3Digest pDigest)
    {
        /* Store the digest */
        theDigest = pDigest;
    }

    public String getAlgorithmName()
    {
        return theDigest.getAlgorithmName() + "Mac";
    }

    public void init(final CipherParameters pParams)
    {
        CipherParameters myParams = pParams;
        if (myParams instanceof KeyParameter)
        {
            myParams = Blake3Parameters.key(((KeyParameter)myParams).getKey());
        }
        if (!(myParams instanceof Blake3Parameters))
        {
            throw new IllegalArgumentException("Invalid parameter passed to Blake3Mac init - "
                + pParams.getClass().getName());
        }
        final Blake3Parameters myBlakeParams = (Blake3Parameters)myParams;
        if (myBlakeParams.getKey() == null)
        {
            throw new IllegalArgumentException("Blake3Mac requires a key parameter.");
        }

        /* Configure the digest */
        theDigest.init(myBlakeParams);
    }

    public int getMacSize()
    {
        return theDigest.getDigestSize();
    }

    public void update(final byte in)
    {
        theDigest.update(in);
    }

    public void update(final byte[] in, final int inOff, final int len)
    {
        theDigest.update(in, inOff, len);
    }

    public int doFinal(final byte[] out, final int outOff)
    {
        return theDigest.doFinal(out, outOff);
    }

    public void reset()
    {
        theDigest.reset();
    }
}
