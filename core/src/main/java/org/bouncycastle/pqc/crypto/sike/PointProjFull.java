package org.bouncycastle.pqc.crypto.sike;

class PointProjFull
{
    PointProjFull(int nwords_field)
    {
        X = new long[2][nwords_field];
        Y = new long[2][nwords_field];
        Z = new long[2][nwords_field];
    }
    long[][] X;
    long[][] Y;
    long[][] Z;
}
