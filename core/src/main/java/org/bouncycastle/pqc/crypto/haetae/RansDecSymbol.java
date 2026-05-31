package org.bouncycastle.pqc.crypto.haetae;

class RansDecSymbol
{
    public final int start; // Start of range
    public final int freq;  // Symbol frequency

    public RansDecSymbol(int start, int freq)
    {
        this.start = start;
        this.freq = freq;
    }
}