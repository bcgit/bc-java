package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;

public class LMSParameterSet {

    final LMType set;
    final Digest hash;
    final int n;
    final int height;


    public LMSParameterSet(LMType set, Digest hash, int n, int height)
    {
        this.set = set;
        this.hash = hash;
        this.n = n;
        this.height = height;
    }
}
