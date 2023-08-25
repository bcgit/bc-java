package org.bouncycastle.pqc.math.ntru.parameters;

/**
 * NTRU-HPS parameter set with n = 677 and q = 2048.
 *
 * @see NTRUHPSParameterSet
 */
public class NTRUHPS2048677
    extends NTRUHPSParameterSet
{

    public NTRUHPS2048677()
    {
        super(
            677,
            11,
            32,
            32,
            32 // Category 3 (local model) - KATs based on 256 bit
        );
    }
}
