package org.bouncycastle.pqc.crypto.cross;

class Utils
{
    // Calculate bits needed to represent a number
    public static int bitsToRepresent(int n)
    {
        return 32 - Integer.numberOfLeadingZeros(n);
    }
}
