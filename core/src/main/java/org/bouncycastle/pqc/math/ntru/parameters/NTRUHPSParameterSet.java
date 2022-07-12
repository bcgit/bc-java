package org.bouncycastle.pqc.math.ntru.parameters;

import org.bouncycastle.pqc.math.ntru.HPSPolynomial;
import org.bouncycastle.pqc.math.ntru.Polynomial;

/**
 * Abstract class for NTRU-HPS parameter classes.
 * <p>
 * The naming convention for the classes is {@code NTRUHPS[q][n]}. e.g. {@link NTRUHPS2048509} has n = 509 and q = 2048.
 *
 * @see NTRUHPS2048509
 * @see NTRUHPS2048677
 * @see NTRUHPS4096821
 * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification document</a> section 1.3.2
 */
public abstract class NTRUHPSParameterSet
    extends NTRUParameterSet
{
    NTRUHPSParameterSet(int n, int logQ, int seedBytes, int prfKeyBytes, int sharedKeyBytes)
    {
        super(n, logQ, seedBytes, prfKeyBytes, sharedKeyBytes);
    }

    @Override
    public Polynomial createPolynomial()
    {
        return new HPSPolynomial(this);
    }

    @Override
    public int sampleFgBytes()
    {
        return sampleIidBytes() + sampleFixedTypeBytes();
    }

    @Override
    public int sampleRmBytes()
    {
        return sampleIidBytes() + sampleFixedTypeBytes();
    }

    public int weight()
    {
        return q() / 8 - 2;
    }
}
