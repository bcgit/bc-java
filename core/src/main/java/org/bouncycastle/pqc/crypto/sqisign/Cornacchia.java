package org.bouncycastle.pqc.crypto.sqisign;

/**
 * Cornacchia's algorithm for representing a prime {@code p} as
 * {@code x² + n·y²}, returning positive integers {@code x} and {@code y}.
 * Java port of {@code ibz_cornacchia_prime} from
 * {@code src/quaternion/ref/generic/integers.c}.
 *
 * <p>Used by the SQIsign quaternion norm-equation solver to find an algebra
 * element with a specific reduced norm.</p>
 */
final class Cornacchia
{
    private Cornacchia()
    {
    }

    /**
     * Solve {@code x² + n·y² = p} for positive integers {@code x, y}.
     * Assumes {@code p} is prime and {@code -n} is a quadratic residue
     * modulo {@code p}.
     *
     * @return 1 on success (and writes {@code x, y}), 0 on failure (no
     *         representation, or {@code -n} is not a QR).
     */
    public static int cornacchiaPrime(Ibz x, Ibz y, Ibz n, Ibz p)
    {
        // Special case p == 2
        if (Ibz.cmp(p, Ibz.TWO) == 0)
        {
            if (Ibz.isOne(n) == 1)
            {
                Ibz.set(x, 1);
                Ibz.set(y, 1);
                return 1;
            }
            return 0;
        }

        // Special case p == n
        if (Ibz.cmp(p, n) == 0)
        {
            Ibz.set(x, 0);
            Ibz.set(y, 1);
            return 1;
        }

        // p and n must be coprime
        Ibz g = new Ibz();
        Ibz.gcd(g, p, n);
        if (Ibz.isOne(g) != 1)
        {
            return 0;
        }

        // r2 = sqrt(-n) mod p
        Ibz negN = new Ibz();
        Ibz.neg(negN, n);
        Ibz r2 = new Ibz();
        if (Ibz.sqrtModP(r2, negN, p) != 1)
        {
            return 0;
        }

        // Euclidean loop: maintain (r2, r1) and stop when r0² < p.
        // C variables: r0 (current quotient stage), r1, r2 (working values),
        // a (scratch quotient), prod (r0² accumulator).
        Ibz r0 = new Ibz();
        Ibz r1 = new Ibz();
        Ibz a = new Ibz();
        Ibz prod = new Ibz();
        Ibz.copy(prod, p);
        Ibz.copy(r1, p);
        Ibz.copy(r0, p);

        while (Ibz.cmp(prod, p) >= 0)
        {
            Ibz.div(a, r0, r2, r1);
            Ibz.mul(prod, r0, r0);
            Ibz.copy(r2, r1);
            Ibz.copy(r1, r0);
        }

        // Verify: (p - r0²) divisible by n, and (p - r0²)/n is a perfect square.
        Ibz diff = new Ibz();
        Ibz.sub(diff, p, prod);
        Ibz scratch = new Ibz();
        Ibz.div(a, scratch, diff, n);  // a = (p - r0²) / n if exact; scratch = remainder
        if (Ibz.isZero(scratch) != 1)
        {
            return 0;
        }
        if (Ibz.sqrt(y, a) != 1)
        {
            return 0;
        }

        Ibz.copy(x, r0);

        // Final sanity check: x² + n·y² == p
        Ibz check = new Ibz();
        Ibz.mul(check, y, y);
        Ibz.mul(check, check, n);
        Ibz.add(check, check, prod);
        return Ibz.cmp(check, p) == 0 ? 1 : 0;
    }

}
