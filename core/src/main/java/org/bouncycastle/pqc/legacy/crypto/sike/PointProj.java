package org.bouncycastle.pqc.legacy.crypto.sike;

class PointProj
{
    PointProj(int nwords_field)
    {
        X = new long[2][nwords_field];
        Z = new long[2][nwords_field];
    }
    long[][] X;
    long[][] Z;
}
