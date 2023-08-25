package org.bouncycastle.pqc.math.ntru.parameters;

/**
 * NTRU-HPS parameter set with n = 509 and q = 2048.
 *
 * @see NTRUHPSParameterSet
 */
public class NTRUHPS2048509
    extends NTRUHPSParameterSet
{
    public NTRUHPS2048509()
    {
        super(
            509,
            11,
            32,
            32,
            32     // category 1 (local model)
        );
    }
}
