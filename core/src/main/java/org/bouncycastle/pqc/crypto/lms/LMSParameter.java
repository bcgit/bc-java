package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public abstract class LMSParameter
{
    private final int type;
    private final int m;
    private final int h;


    protected LMSParameter(int type, int m, int h)
    {
        this.type = type;
        this.m = m;
        this.h = h;
    }


    public abstract ASN1ObjectIdentifier getDigestOID();

    public int getType()
    {
        return type;
    }

    public int getH()
    {
        return h;
    }

    public int getM()
    {
        return m;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        LMSParameter that = (LMSParameter)o;

        if (type != that.type)
        {
            return false;
        }
        if (m != that.m)
        {
            return false;
        }
        return h == that.h;
    }

    @Override
    public int hashCode()
    {
        int result = type;
        result = 31 * result + m;
        result = 31 * result + h;
        return result;
    }


}
