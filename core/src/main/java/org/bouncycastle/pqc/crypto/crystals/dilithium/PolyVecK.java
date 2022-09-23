package org.bouncycastle.pqc.crypto.crystals.dilithium;

class PolyVecK
{
    Poly[] vec;
    private DilithiumEngine engine;
    private int mode;
    private int polyVecBytes;
    private int dilithiumK;
    private int dilithiumL;

    public PolyVecK(DilithiumEngine engine)
    {
        this.engine = engine;
        this.mode = engine.getDilithiumMode();
        this.dilithiumK = engine.getDilithiumK();
        this.dilithiumL = engine.getDilithiumL();

        this.vec = new Poly[dilithiumK];
        for (int i = 0; i < dilithiumK; i++)
        {
            vec[i] = new Poly(engine);
        }
    }

    public PolyVecK()
        throws Exception
    {
        throw new Exception("Requires Parameter");
    }

    public Poly getVectorIndex(int i)
    {
        return vec[i];
    }

    public void setVectorIndex(int i, Poly p)
    {
        this.vec[i] = p;
    }

    public void uniformEta(byte[] seed, short nonce)
    {
        int i;
        short n = nonce;
        for (i = 0; i < dilithiumK; ++i)
        {
            getVectorIndex(i).uniformEta(seed, n++);
        }

    }

    public void reduce()
    {
        for (int i = 0; i < dilithiumK; ++i)
        {
            this.getVectorIndex(i).reduce();
        }
    }

    public void invNttToMont()
    {
        for (int i = 0; i < dilithiumK; ++i)
        {
            this.getVectorIndex(i).invNttToMont();
        }
    }

    public void addPolyVecK(PolyVecK b)
    {
        for (int i = 0; i < dilithiumK; ++i)
        {
            this.getVectorIndex(i).addPoly(b.getVectorIndex(i));
        }
    }

    public void conditionalAddQ()
    {
        for (int i = 0; i < dilithiumK; ++i)
        {
            this.getVectorIndex(i).conditionalAddQ();
        }
    }

    public void power2Round(PolyVecK pvk)
    {
        for (int i = 0; i < dilithiumK; ++i)
        {
            this.getVectorIndex(i).power2Round(pvk.getVectorIndex(i));
        }
    }

    public void polyVecNtt()
    {
        int i;
        for (i = 0; i < dilithiumK; ++i)
        {
            this.vec[i].polyNtt();
        }
    }

    public void decompose(PolyVecK v)
    {
        for (int i = 0; i < dilithiumK; ++i)
        {
            this.getVectorIndex(i).decompose(v.getVectorIndex(i));
        }
    }

    public byte[] packW1()
    {
        byte[] out = new byte[dilithiumK * engine.getDilithiumPolyW1PackedBytes()];
        int i;
        for (i = 0; i < dilithiumK; ++i)
        {
            System.arraycopy(this.getVectorIndex(i).w1Pack(), 0, out, i * engine.getDilithiumPolyW1PackedBytes(), engine.getDilithiumPolyW1PackedBytes());
        }
        return out;
    }

    public void pointwisePolyMontgomery(Poly a, PolyVecK v)
    {
        for (int i = 0; i < dilithiumK; ++i)
        {
            this.getVectorIndex(i).pointwiseMontgomery(a, v.getVectorIndex(i));
        }
    }

    public void subtract(PolyVecK inpVec)
    {
        for (int i = 0; i < dilithiumK; ++i)
        {
            this.getVectorIndex(i).subtract(inpVec.getVectorIndex(i));
        }
    }

    public boolean checkNorm(int bound)
    {
        for (int i = 0; i < dilithiumK; ++i)
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
        int i, s = 0;
        for (i = 0; i < dilithiumK; ++i)
        {
            s += this.getVectorIndex(i).polyMakeHint(v0.getVectorIndex(i), v1.getVectorIndex(i));
        }

        return s;
    }

    public void useHint(PolyVecK u, PolyVecK h)
    {
        for (int i = 0; i < dilithiumK; ++i)
        {
            this.getVectorIndex(i).polyUseHint(u.getVectorIndex(i), h.getVectorIndex(i));
        }
    }

    public void shiftLeft()
    {
        for (int i = 0; i < dilithiumK; ++i)
        {
            this.getVectorIndex(i).shiftLeft();
        }
    }

    @Override
    public String toString()
    {
        String out = "[";
        for (int i = 0; i < dilithiumK; i++)
        {
            out += i + " " + this.getVectorIndex(i).toString();
            if (i == dilithiumK - 1)
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
