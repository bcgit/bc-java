package org.bouncycastle.pqc.crypto.hawk;

class Fxc
{
    long re;  // Real part (fixed-point representation)
    long im;  // Imaginary part (fixed-point representation)

    // Default constructor
    public Fxc()
    {
        this.re = 0;
        this.im = 0;
    }

    // Constructor with initial values
    public Fxc(long re, long im)
    {
        this.re = re;
        this.im = im;
    }

    // Copy constructor
    public Fxc(Fxc other)
    {
        this.re = other.re;
        this.im = other.im;
    }

    // Complex multiplication
    public static Fxc mul(Fxc x, Fxc y)
    {
        /*
         * We are computing r = (a + i*b)*(c + i*d) with:
         *   z0 = a*c
         *   z1 = b*d
         *   z2 = (a + b)*(c + d)
         *   r = (z0 - z1) + i*(z2 - (z0 + z1))
         */
        long z0 = fxrMul(x.re, y.re);
        long z1 = fxrMul(x.im, y.im);
        long z2 = fxrMul(fxrAdd(x.re, x.im), fxrAdd(y.re, y.im));

        Fxc result = new Fxc();
        result.re = fxrSub(z0, z1);
        result.im = fxrSub(z2, fxrAdd(z0, z1));
        return result;
    }

    // Complex addition
    public static Fxc add(Fxc x, Fxc y)
    {
        Fxc result = new Fxc();
        result.re = fxrAdd(x.re, y.re);
        result.im = fxrAdd(x.im, y.im);
        return result;
    }

    // Complex subtraction
    public static Fxc sub(Fxc x, Fxc y)
    {
        Fxc result = new Fxc();
        result.re = fxrSub(x.re, y.re);
        result.im = fxrSub(x.im, y.im);
        return result;
    }

    // Fixed-point multiplication
    private static long fxrMul(long x, long y)
    {
        // Extract high and low parts
        int xh = (int)(x >> 32);
        int yh = (int)(y >> 32);
        long xl = x & 0xFFFFFFFFL;
        long yl = y & 0xFFFFFFFFL;

        // Compute partial products
        long z0 = (xl * yl) >>> 32;
        long z1 = xl * yh;
        long z2 = yl * xh;
        long z3 = ((long)xh * yh) << 32;

        return z0 + z1 + z2 + z3;
    }

    // Fixed-point addition
    private static long fxrAdd(long x, long y)
    {
        return x + y;
    }

    // Fixed-point subtraction
    private static long fxrSub(long x, long y)
    {
        return x - y;
    }

    // Convert to string for debugging
    @Override
    public String toString()
    {
        return String.format("(%f, %f)", re / (double)(1L << 32), im / (double)(1L << 32));
    }

    // Equality check
    @Override
    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (obj == null || getClass() != obj.getClass())
        {
            return false;
        }
        Fxc other = (Fxc)obj;
        return re == other.re && im == other.im;
    }

    // Hash code
//    @Override
//    public int hashCode()
//    {
//        return Long.hashCode(re) ^ Long.hashCode(im);
//    }
}
