package org.bouncycastle.pqc.crypto.mldsa;

class PolyVecL
{
    private final Poly[] vec;

    PolyVecL(MLDSAEngine engine)
    {
        int dilithiumL = engine.getDilithiumL();

        this.vec = new Poly[dilithiumL];
        for (int i = 0; i < dilithiumL; i++)
        {
            vec[i] = new Poly(engine);
        }
    }

    public PolyVecL()
        throws Exception
    {
        throw new Exception("Requires Parameter");
    }

    public Poly getVectorIndex(int i)
    {
        return vec[i];
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
        int i;
        short n = nonce;
        for (i = 0; i < vec.length; ++i)
        {
            getVectorIndex(i).uniformEta(seed, n++);
        }

    }

    void copyTo(PolyVecL z)
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
            this.vec[i].polyNtt();
        }
    }

    public void uniformGamma1(byte[] seed, short nonce)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).uniformGamma1(seed, (short)(vec.length * nonce + i));
        }
    }

    public void pointwisePolyMontgomery(Poly a, PolyVecL v)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).pointwiseMontgomery(a, v.getVectorIndex(i));
        }
    }

    public void invNttToMont()
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).invNttToMont();
        }
    }

    public void addPolyVecL(PolyVecL v)
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).addPoly(v.getVectorIndex(i));
        }
    }

    public void reduce()
    {
        for (int i = 0; i < vec.length; ++i)
        {
            this.getVectorIndex(i).reduce();
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

    @Override
    public String toString()
    {
        String out = "\n[";
        for (int i = 0; i < vec.length; i++)
        {
            out += "Inner Matrix " + i + " " + this.getVectorIndex(i).toString();
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
