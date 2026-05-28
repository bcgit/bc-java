package org.bouncycastle.pqc.crypto.haetae;

class RansEncSymbol
{
    public final int x_max;      // (Exclusive) upper bound of pre‑normalization interval
    public final int rcp_freq;   // Fixed‑point reciprocal frequency
    public final int bias;       // Bias
    public final int cmpl_freq;  // Complement of frequency: (1 << scale_bits) - freq
    public final int rcp_shift;  // Reciprocal shift

    public RansEncSymbol(int x_max, int rcp_freq, int bias, int cmpl_freq, int rcp_shift)
    {
        this.x_max = x_max;
        this.rcp_freq = rcp_freq;
        this.bias = bias;
        this.cmpl_freq = cmpl_freq;
        this.rcp_shift = rcp_shift;
    }
}
