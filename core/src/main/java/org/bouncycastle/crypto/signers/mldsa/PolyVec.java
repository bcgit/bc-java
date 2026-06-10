package org.bouncycastle.crypto.signers.mldsa;

class PolyVec
{
    private final Poly[] vec;

    PolyVec(MLDSAEngine engine, int length)
    {
        this.vec = new Poly[length];
        for (int i = 0; i < length; i++)
        {
            vec[i] = new Poly(engine);
        }
    }

    Poly getVectorIndex(int i)
    {
        return vec[i];
    }

    int length()
    {
        return vec.length;
    }

    void uniformBlocks(byte[] rho, int t)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].uniformBlocks(rho, (short)(t + i));
        }
    }

    public void uniformEta(byte[] seed, short nonce)
    {
        short n = nonce;
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].uniformEta(seed, n++);
        }
    }

    public void uniformGamma1(byte[] seed, short nonce)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].uniformGamma1(seed, (short)(vec.length * nonce + i));
        }
    }

    void copyTo(PolyVec z)
    {
        for (int i = 0; i < vec.length; i++)
        {
            vec[i].copyTo(z.vec[i]);
        }
    }

    public void polyVecNtt()
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].polyNtt();
        }
    }

    public void invNttToMont()
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].invNttToMont();
        }
    }

    public void reduce()
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].reduce();
        }
    }

    public void conditionalAddQ()
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].conditionalAddQ();
        }
    }

    public void addPolyVec(PolyVec b)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].addPoly(b.vec[i]);
        }
    }

    public void subtract(PolyVec inpVec)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].subtract(inpVec.vec[i]);
        }
    }

    public void pointwisePolyMontgomery(Poly a, PolyVec v)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].pointwiseMontgomery(a, v.vec[i]);
        }
    }

    public void power2Round(PolyVec pv)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].power2Round(pv.vec[i]);
        }
    }

    public void decompose(PolyVec v)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].decompose(v.vec[i]);
        }
    }

    public int makeHint(PolyVec v0, PolyVec v1)
    {
        int s = 0;
        for (int i = 0; i < vec.length; ++i)
        {
            s += vec[i].polyMakeHint(v0.vec[i], v1.vec[i]);
        }
        return s;
    }

    public void useHint(PolyVec u, PolyVec h)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].polyUseHint(u.vec[i], h.vec[i]);
        }
    }

    public void shiftLeft()
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].shiftLeft();
        }
    }

    public void packW1(MLDSAEngine engine, byte[] r, int rOff)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].packW1(r, rOff + i * engine.getDilithiumPolyW1PackedBytes());
        }
    }

    public boolean checkNorm(int bound)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            if (vec[i].checkNorm(bound))
            {
                return true;
            }
        }
        return false;
    }
}
