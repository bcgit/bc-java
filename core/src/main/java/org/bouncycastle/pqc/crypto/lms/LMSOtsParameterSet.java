package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;

public class LMSOtsParameterSet
{
    final Digest h;
    final int n;
    final int w;
    final int p;
    final int ls;

    public LMSOtsParameterSet(Digest h, int n, int w, int p, int ls)
    {
        this.h = h;
        this.n = n;
        this.w = w;
        this.p = p;
        this.ls = ls;
    }
}
