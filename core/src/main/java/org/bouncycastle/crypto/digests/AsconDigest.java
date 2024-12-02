package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Pack;

/**
 * ASCON v1.2 Digest, https://ascon.iaik.tugraz.at/ .
 * <p>
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
 * <p>
 * ASCON v1.2 Digest with reference to C Reference Impl from: https://github.com/ascon/ascon-c .
 *
 * @deprecated use Ascon Hash 256 Digest
 */
public class AsconDigest
    extends AsconBaseDigest
{
    public enum AsconParameters
    {
        AsconHash,
        AsconHashA,
    }

    AsconParameters asconParameters;

    public AsconDigest(AsconParameters parameters)
    {
        this.asconParameters = parameters;
        switch (parameters)
        {
        case AsconHash:
            ASCON_PB_ROUNDS = 12;
            algorithmName = "Ascon-Hash";
            break;
        case AsconHashA:
            ASCON_PB_ROUNDS = 8;
            algorithmName = "Ascon-HashA";
            break;
        default:
            throw new IllegalArgumentException("Invalid parameter settings for Ascon Hash");
        }
        reset();
    }

    private final String algorithmName;

    protected long pad(int i)
    {
        return 0x80L << (56 - (i << 3));
    }

    protected long loadBytes(final byte[] bytes, int inOff)
    {
        return Pack.bigEndianToLong(bytes, inOff);
    }

    protected long loadBytes(final byte[] bytes, int inOff, int n)
    {
        return Pack.bigEndianToLong(bytes, inOff, n);
    }

    protected void setBytes(long w, byte[] bytes, int inOff)
    {
        Pack.longToBigEndian(w, bytes, inOff);
    }

    protected void setBytes(long w, byte[] bytes, int inOff, int n)
    {
        Pack.longToBigEndian(w, bytes, inOff, n);
    }

    @Override
    public String getAlgorithmName()
    {
        return algorithmName;
    }

    @Override
    public void reset()
    {
        super.reset();
        /* initialize */
        switch (asconParameters)
        {
        case AsconHashA:
            x0 = 92044056785660070L;
            x1 = 8326807761760157607L;
            x2 = 3371194088139667532L;
            x3 = -2956994353054992515L;
            x4 = -6828509670848688761L;
            break;
        case AsconHash:
            x0 = -1255492011513352131L;
            x1 = -8380609354527731710L;
            x2 = -5437372128236807582L;
            x3 = 4834782570098516968L;
            x4 = 3787428097924915520L;
            break;
        }
    }
}
