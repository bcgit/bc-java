package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public abstract class LmsParameter
{
    private final int type;
    private final int m;
    private final int h;


    protected LmsParameter(int type, int m, int h)
    {
        this.type = type;
        this.m = m;
        this.h = h;
    }


    public abstract Digest getDigest();

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

        LmsParameter that = (LmsParameter)o;

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

    public static class LMS_SHA256_M32_H5
        extends LmsParameter
    {

        public LMS_SHA256_M32_H5()
        {
            super(5, 32, 5);
        }

        @Override
        public Digest getDigest()
        {
            return new SHA256Digest();
        }
    }

    public static class LMS_SHA256_M32_H10
        extends LmsParameter
    {

        public LMS_SHA256_M32_H10()
        {
            super(6, 32, 10);
        }

        @Override
        public Digest getDigest()
        {
            return new SHA256Digest();
        }


    }

    public static class LMS_SHA256_M32_H15
        extends LmsParameter
    {

        public LMS_SHA256_M32_H15()
        {
            super(7, 32, 15);
        }

        @Override
        public Digest getDigest()
        {
            return new SHA256Digest();
        }
    }

    public static class LMS_SHA256_M32_H20
        extends LmsParameter
    {

        public LMS_SHA256_M32_H20()
        {
            super(8, 32, 20);
        }

        @Override
        public Digest getDigest()
        {
            return new SHA256Digest();
        }
    }

    public static class LMS_SHA256_M32_H25
        extends LmsParameter
    {

        public LMS_SHA256_M32_H25()
        {
            super(9, 32, 25);
        }

        @Override
        public Digest getDigest()
        {
            return new SHA256Digest();
        }
    }

}
