package org.bouncycastle.pqc.crypto.mldsa;

class PolyVecK
{
    private final Poly[] vec;

    PolyVecK(MLDSAEngine engine)
    {
        int dilithiumK = engine.getDilithiumK();

        this.vec = new Poly[dilithiumK];
        for (int i = 0; i < dilithiumK; i++)
        {
            vec[i] = new Poly(engine);
        }
    }

    Poly getVectorIndex(int i)
    {
        return vec[i];
    }

    void setVectorIndex(int i, Poly p)
    {
        this.vec[i] = p;
    }

    public void uniformEta(byte[] seed, short nonce)
    {
        short n = nonce;
        for (int i = 0; i < vec.length; ++i)
        {
            vec[i].uniformEta(seed, n++);
        }
    }

    public void reduce()
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).reduce();
        }
    }

    public void invNttToMont()
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).invNttToMont();
        }
    }

    public void addPolyVecK(PolyVecK b)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).addPoly(b.getVectorIndex(i));
        }
    }

    public void conditionalAddQ()
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).conditionalAddQ();
        }
    }

    public void power2Round(PolyVecK pvk)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).power2Round(pvk.getVectorIndex(i));
        }
    }

    public void polyVecNtt()
    {
        int i;
        for (i = 0; i < vec.length; ++i)
        {
            this.vec[i].polyNtt();
        }
    }

    public void decompose(PolyVecK v)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).decompose(v.getVectorIndex(i));
        }
    }

    public void packW1(MLDSAEngine engine, byte[] r, int rOff)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            getVectorIndex(i).packW1(r, rOff + i * engine.getDilithiumPolyW1PackedBytes());
        }
    }

    public void pointwisePolyMontgomery(Poly a, PolyVecK v)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).pointwiseMontgomery(a, v.getVectorIndex(i));
        }
    }

    public void subtract(PolyVecK inpVec)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).subtract(inpVec.getVectorIndex(i));
        }
    }

    public boolean checkNorm(int bound)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            if (this.getVectorIndex(i).checkNorm(bound))
            {
                return true;
            }
        }

        return false;
    }

    public int makeHint(PolyVecK v0, PolyVecK v1)
    {
        int s = 0;
        for (int i = 0; i < vec.length; ++i)
        {
            s += this.getVectorIndex(i).polyMakeHint(v0.getVectorIndex(i), v1.getVectorIndex(i));
        }

        return s;
    }

    public void useHint(PolyVecK u, PolyVecK h)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).polyUseHint(u.getVectorIndex(i), h.getVectorIndex(i));
        }
    }

    public void shiftLeft()
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).shiftLeft();
        }
    }

    @Override
    public String toString()
    {
        String out = "[";
        for (int i = 0; i < vec.length; i++)
        {
            out += i + " " + this.getVectorIndex(i).toString();
            if (i == vec.length - 1)
            {
                continue;
            }
            out += ",\n";
        }
        out += "]";
        return out;
    }

    public String toString(String name)
    {
        return name + ": " + this.toString();
    }
}
