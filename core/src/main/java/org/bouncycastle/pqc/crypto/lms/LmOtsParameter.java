package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public abstract class LmOtsParameter
{
    private final int type;
    private final int n;
    private final int w;
    private final int p;
    private final int ls;
    private final int sigLen;

    protected LmOtsParameter(int type, int n, int w, int p, int ls, int sigLen)
    {
        this.type = type;
        this.n = n;
        this.w = w;
        this.p = p;
        this.ls = ls;
        this.sigLen = sigLen;
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

        LmOtsParameter parameter = (LmOtsParameter)o;

        if (type != parameter.type)
        {
            return false;
        }
        if (n != parameter.n)
        {
            return false;
        }
        if (w != parameter.w)
        {
            return false;
        }
        if (p != parameter.p)
        {
            return false;
        }
        if (ls != parameter.ls)
        {
            return false;
        }
        return sigLen == parameter.sigLen;
    }

    @Override
    public int hashCode()
    {
        int result = type;
        result = 31 * result + n;
        result = 31 * result + w;
        result = 31 * result + p;
        result = 31 * result + ls;
        result = 31 * result + sigLen;
        return result;
    }

    public abstract Digest getH();



    public static class LMOTS_SHA256_N32_W1
        extends LmOtsParameter
    {

        public LMOTS_SHA256_N32_W1()
        {
            super(1, 32, 1, 265, 7, 8516);
        }

        @Override
        public Digest getH()
        {
            return new SHA256Digest();
        }
    }

    public static class LMOTS_SHA256_N32_W2
        extends LmOtsParameter
    {

        public LMOTS_SHA256_N32_W2()
        {
            super(2, 32, 2, 133, 6, 4292);
        }

        @Override
        public Digest getH()
        {
            return new SHA256Digest();
        }
    }

    public static class LMOTS_SHA256_N32_W4
        extends LmOtsParameter
    {

        public LMOTS_SHA256_N32_W4()
        {
            super(3, 32, 4, 67, 4, 2180);
        }

        @Override
        public Digest getH()
        {
            return new SHA256Digest();
        }
    }

    public static class LMOTS_SHA256_N32_W8
        extends LmOtsParameter
    {

        public LMOTS_SHA256_N32_W8()
        {
            super(4, 32, 8, 34, 0, 1124);
        }

        @Override
        public Digest getH()
        {
            return new SHA256Digest();
        }
    }


    public abstract static class LMOTS_CUSTOM
        extends LmOtsParameter
    {

        public LMOTS_CUSTOM(int type, int n, int w, int p, int ls, int sigLen)
        {
            super(type, n, w, p, ls, sigLen);
        }

    }

}
