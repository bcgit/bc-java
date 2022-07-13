package org.bouncycastle.pqc.math.ntru.parameters;


/**
 * NTRU-HRSS parameter set with n = 701.
 *
 * @see NTRUHRSSParameterSet
 */
public class NTRUHRSS701
    extends NTRUHRSSParameterSet
{
    public NTRUHRSS701()
    {
        super(
            701,
            13,
            32,
            32,
            24 // Category 3 (local model) - KATs based on 256 bit
        );
    }
}
