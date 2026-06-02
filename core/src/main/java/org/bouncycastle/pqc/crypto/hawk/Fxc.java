package org.bouncycastle.pqc.crypto.hawk;

/**
 * Immutable fixed-point complex value (Q32.32 real and imaginary parts) used to
 * hold the precomputed FFT twiddle factors in {@link Utils#GM_TAB}. The FFT
 * butterflies in {@link HawkEngine} read the {@code re}/{@code im} fields
 * directly and do the arithmetic inline, so no instance methods are needed here.
 */
class Fxc
{
    long re;  // Real part (fixed-point representation)
    long im;  // Imaginary part (fixed-point representation)

    public Fxc(long re, long im)
    {
        this.re = re;
        this.im = im;
    }

    @Override
    public String toString()
    {
        return "(" + (re / (double)(1L << 32)) + ", " + (im / (double)(1L << 32)) + ")";
    }

    @Override
    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (obj == null || getClass() != obj.getClass())
        {
            return false;
        }
        Fxc other = (Fxc)obj;
        return re == other.re && im == other.im;
    }
}
