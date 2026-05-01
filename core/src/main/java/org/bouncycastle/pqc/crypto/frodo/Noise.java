package org.bouncycastle.pqc.crypto.frodo;

abstract class Noise
{
    static void sample(short[] cdf, short[] r, int rOff, short[] s) 
    {
        // No need to compare with the last value.
//        assert cdf[cdf.length - 1] == 0x7FFF;

        // Fills 's' with samples from the noise distribution 'cdf' using pseudo-random values 'r[rOff..]' 
        for (int i = 0, n = s.length; i < n; ++i)
        {
            int sample = 0;
            int r_i = r[rOff + i] & 0xFFFF;
            int prnd = r_i >>> 1;   // Drop the least significant bit
            int sign = r_i & 1;     // Pick the least significant bit

            for (int j = 0; j < cdf.length - 1; ++j)
            {
                // Constant time comparison: 1 if cdf[j] < prnd, 0 otherwise.
                sample += (cdf[j] - prnd) >>> 31;
            }

            // Assuming that sign is either 0 or 1, flips sample iff sign = 1
            sample = ((-sign) ^ sample) + sign;

            s[i] = (short)sample;
        }
    }    
}
