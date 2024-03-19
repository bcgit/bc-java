package org.bouncycastle.pqc.math.ntru.parameters;


/**
 * NTRU-HRSS parameter set with n = 701.
 *
 * @see NTRUHRSSParameterSet
 */
public class NTRUHRSS1373
    extends NTRUHRSSParameterSet
{
    public NTRUHRSS1373()
    {
        super(
            1373,
            14,
            32,
            32,
            32 // Category 5 (local model) - KATs based on 256 bit
        );
    }
}
