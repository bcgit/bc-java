package org.bouncycastle.pqc.crypto.crystals.dilithium;

class PolyVecL
{
    Poly[] vec;
    private DilithiumEngine engine;
    private int mode;
    private int polyVecBytes;
    private int dilithiumL;
    private int dilithiumK;

    public PolyVecL(DilithiumEngine engine)
    {
        this.engine = engine;
        this.mode = engine.getDilithiumMode();
        this.dilithiumL = engine.getDilithiumL();
        this.dilithiumK = engine.getDilithiumK();

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

    public void expandMatrix(byte[] rho, int i)
    {
        int j;
        for (j = 0; j < dilithiumL; j++)
        {
            vec[j].uniformBlocks(rho, (short)((i << 8) + j));
        }
    }

    public void uniformEta(byte[] seed, short nonce)
    {
        int i;
        short n = nonce;
        for (i = 0; i < dilithiumL; ++i)
        {
            getVectorIndex(i).uniformEta(seed, n++);
        }

    }

    public void copyPolyVecL(PolyVecL outPoly)
    {
        for (int i = 0; i < dilithiumL; i++)
        {
            for (int j = 0; j < DilithiumEngine.DilithiumN; j++)
            {
                outPoly.getVectorIndex(i).setCoeffIndex(j, this.getVectorIndex(i).getCoeffIndex(j));
            }
        }
    }

    public void polyVecNtt()
    {
        int i;
        for (i = 0; i < dilithiumL; ++i)
        {
            this.vec[i].polyNtt();
        }
    }

    public void uniformGamma1(byte[] seed, short nonce)
    {
        int i;
        for (i = 0; i < dilithiumL; ++i)
        {
            this.getVectorIndex(i).uniformGamma1(seed, (short)(dilithiumL * nonce + i));
        }

    }

    public void pointwisePolyMontgomery(Poly a, PolyVecL v)
    {
        for (int i = 0; i < dilithiumL; ++i)
        {
            this.getVectorIndex(i).pointwiseMontgomery(a, v.getVectorIndex(i));
        }
    }

    public void invNttToMont()
    {
        for (int i = 0; i < dilithiumL; ++i)
        {
            this.getVectorIndex(i).invNttToMont();
        }
    }

    public void addPolyVecL(PolyVecL v)
    {
        for (int i = 0; i < dilithiumL; ++i)
        {
            this.getVectorIndex(i).addPoly(v.getVectorIndex(i));
        }
    }

    public void reduce()
    {
        for (int i = 0; i < dilithiumL; ++i)
        {
            this.getVectorIndex(i).reduce();
        }
    }

    public boolean checkNorm(int bound)
    {
        for (int i = 0; i < dilithiumL; ++i)
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
        for (int i = 0; i < dilithiumL; i++)
        {
            out += "Inner Matrix " + i + " " + this.getVectorIndex(i).toString();
            if (i == dilithiumL - 1)
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
