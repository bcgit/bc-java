package org.bouncycastle.pqc.crypto.ntru;

import org.bouncycastle.pqc.math.ntru.HPSPolynomial;
import org.bouncycastle.pqc.math.ntru.Polynomial;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPSParameterSet;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSSParameterSet;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;
import org.bouncycastle.util.Arrays;

/**
 * An OW-CPA secure deterministic public key encryption scheme (DPKE).
 *
 * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.11
 */
class NTRUOWCPA
{
    private final NTRUParameterSet params;
    private final NTRUSampling sampling;

    public NTRUOWCPA(NTRUParameterSet params)
    {
        this.params = params;
        this.sampling = new NTRUSampling(params);
    }

    /**
     * Generate a DPKE key pair.
     *
     * @param seed a random byte array
     * @return DPKE key pair
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.11.1
     */
    public OWCPAKeyPair keypair(byte[] seed)
    {
        byte[] publicKey;
        byte[] privateKey = new byte[this.params.owcpaSecretKeyBytes()];
        int n = this.params.n();
        int q = this.params.q();
        int i;
        PolynomialPair pair;
        Polynomial x3, x4, x5;
        x3 = this.params.createPolynomial();
        x4 = this.params.createPolynomial();
        x5 = this.params.createPolynomial();

        Polynomial f, g, invfMod3 = x3;
        Polynomial gf = x3, invgf = x4, tmp = x5;
        Polynomial invh = x3, h = x3;

        pair = sampling.sampleFg(seed);
        f = pair.f();
        g = pair.g();

        invfMod3.s3Inv(f);
        byte[] fs3ToBytes = f.s3ToBytes(params.owcpaMsgBytes());
        System.arraycopy(fs3ToBytes, 0, privateKey, 0, fs3ToBytes.length);
        byte[] s3Res = invfMod3.s3ToBytes(privateKey.length - this.params.packTrinaryBytes());
        System.arraycopy(s3Res, 0, privateKey, this.params.packTrinaryBytes(), s3Res.length);

        f.z3ToZq();
        g.z3ToZq();

        if (this.params instanceof NTRUHRSSParameterSet)
        {
            /* g = 3*(x-1)*g */
            for (i = n - 1; i > 0; i--)
            {
                g.coeffs[i] = (short)(3 * (g.coeffs[i - 1] - g.coeffs[i]));
            }
            g.coeffs[0] = (short)-(3 * g.coeffs[0]);
        }
        else
        {
            for (i = 0; i < n; i++)
            {
                g.coeffs[i] = (short)(3 * g.coeffs[i]);
            }
        }

        gf.rqMul(g, f);
        invgf.rqInv(gf);

        tmp.rqMul(invgf, f);
        invh.sqMul(tmp, f);
        byte[] sqRes = invh.sqToBytes(privateKey.length - 2 * this.params.packTrinaryBytes());
        System.arraycopy(sqRes, 0, privateKey, 2 * this.params.packTrinaryBytes(), sqRes.length);

        tmp.rqMul(invgf, g);
        h.rqMul(tmp, g);
        publicKey = h.rqSumZeroToBytes(this.params.owcpaPublicKeyBytes());

        return new OWCPAKeyPair(publicKey, privateKey);
    }

    /**
     * DPKE encryption.
     *
     * @param r
     * @param m
     * @param publicKey
     * @return DPKE ciphertext
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.11.3
     */
    public byte[] encrypt(Polynomial r, Polynomial m, byte[] publicKey)
    {
        int i;
        Polynomial x1 = params.createPolynomial(), x2 = params.createPolynomial();
        Polynomial h = x1, liftm = x1;
        Polynomial ct = x2;

        h.rqSumZeroFromBytes(publicKey);

        ct.rqMul(r, h);

        liftm.lift(m);
        for (i = 0; i < params.n(); i++)
        {
            ct.coeffs[i] += liftm.coeffs[i];
        }
        return ct.rqSumZeroToBytes(params.ntruCiphertextBytes());
    }

    /**
     * DPKE decryption.
     *
     * @param ciphertext
     * @param privateKey
     * @return an instance of {@link OWCPADecryptResult} containing {@code packed_rm} and fail flag
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.11.4
     */
    public OWCPADecryptResult decrypt(byte[] ciphertext, byte[] privateKey)
    {
        byte[] sk = privateKey;
        byte[] rm = new byte[params.owcpaMsgBytes()];
        int i, fail;
        Polynomial x1 = params.createPolynomial();
        Polynomial x2 = params.createPolynomial();
        Polynomial x3 = params.createPolynomial();
        Polynomial x4 = params.createPolynomial();

        Polynomial c = x1, f = x2, cf = x3;
        Polynomial mf = x2, finv3 = x3, m = x4;
        Polynomial liftm = x2, invh = x3, r = x4;
        Polynomial b = x1;

        c.rqSumZeroFromBytes(ciphertext);
        f.s3FromBytes(sk);
        f.z3ToZq();

        cf.rqMul(c, f);
        mf.rqToS3(cf);

        finv3.s3FromBytes(Arrays.copyOfRange(sk, params.packTrinaryBytes(), sk.length));
        m.s3Mul(mf, finv3);
        byte[] arr1 = m.s3ToBytes(rm.length - params.packTrinaryBytes());

        fail = 0;

        /* Check that the unused bits of the last byte of the ciphertext are zero */
        fail |= checkCiphertext(ciphertext);

        /* For the IND-CCA2 KEM we must ensure that c = Enc(h, (r,m)).             */
        /* We can avoid re-computing r*h + Lift(m) as long as we check that        */
        /* r (defined as b/h mod (q, Phi_n)) and m are in the message space.       */
        /* (m can take any value in S3 in NTRU_HRSS) */
        if (params instanceof NTRUHPSParameterSet)
        {
            fail |= checkM((HPSPolynomial)m);
        }

        /* b = c - Lift(m) mod (q, x^n - 1) */
        liftm.lift(m);
        for (i = 0; i < params.n(); i++)
        {
            b.coeffs[i] = (short)(c.coeffs[i] - liftm.coeffs[i]);
        }

        /* r = b / h mod (q, Phi_n) */
        invh.sqFromBytes(Arrays.copyOfRange(sk, 2 * params.packTrinaryBytes(), sk.length));
        r.sqMul(b, invh);

        /* NOTE: Our definition of r as b/h mod (q, Phi_n) follows Figure 4 of     */
        /*   [Sch18] https://eprint.iacr.org/2018/1174/20181203:032458.            */
        /* This differs from Figure 10 of Saito--Xagawa--Yamakawa                  */
        /*   [SXY17] https://eprint.iacr.org/2017/1005/20180516:055500             */
        /* where r gets a final reduction modulo p.                                */
        /* We need this change to use Proposition 1 of [Sch18].                    */

        /* Proposition 1 of [Sch18] shows that re-encryption with (r,m) yields c.  */
        /* if and only if fail==0 after the following call to owcpa_check_r        */
        /* The procedure given in Fig. 8 of [Sch18] can be skipped because we have */
        /* c(1) = 0 due to the use of poly_Rq_sum_zero_{to,from}bytes.             */
        fail |= checkR(r);

        r.trinaryZqToZ3();
        byte[] arr2 = r.s3ToBytes(params.owcpaMsgBytes());
        System.arraycopy(arr2, 0, rm, 0, arr2.length);
        System.arraycopy(arr1, 0, rm, params.packTrinaryBytes(), arr1.length);

        return new OWCPADecryptResult(rm, fail);
    }

    private int checkCiphertext(byte[] ciphertext)
    {
        /* A ciphertext is log2(q)*(n-1) bits packed into bytes.  */
        /* Check that any unused bits of the final byte are zero. */
        short t;
        t = ciphertext[params.ntruCiphertextBytes() - 1];
        t &= 0xff << (8 - (7 & (params.logQ() * params.packDegree())));

        /* We have 0 <= t < 256 */
        /* Return 0 on success (t=0), 1 on failure */
        return 1 & ((~t + 1) >>> 15);
    }

    private int checkR(Polynomial r)
    {
        /* A valid r has coefficients in {0,1,q-1} and has r[N-1] = 0 */
        /* Note: We may assume that 0 <= r[i] <= q-1 for all i        */
        int i;
        int t = 0; // unsigned
        short c; // unsigned
        for (i = 0; i < params.n() - 1; i++)
        {
            c = r.coeffs[i];
            t |= (c + 1) & (params.q() - 4); /* 0 iff c is in {-1,0,1,2} */
            t |= (c + 2) & 4; /* 1 if c = 2, 0 if c is in {-1,0,1} */
        }

        t |= r.coeffs[params.n() - 1];/* Coefficient n-1 must be zero */

        /* We have 0 <= t < 2^16. */
        /* Return 0 on success (t=0), 1 on failure */
        return (1 & ((~t + 1) >>> 31));
    }

    /**
     * Check that m is in message space, i.e.
     * (1)  |{i : m[i] = 1}| = |{i : m[i] = 2}|, and
     * (2)  |{i : m[i] != 0}| = NTRU_WEIGHT.
     * Note: We may assume that m has coefficients in {0,1,2}.
     *
     * @param m
     * @return 0 on success (t=0), 1 on failure
     */
    private int checkM(HPSPolynomial m)
    {
        int i;
        int t = 0; // unsigned
        short ps = 0; // unsigned
        short ms = 0; // unsigned
        for (i = 0; i < params.n() - 1; i++)
        {
            ps += m.coeffs[i] & 1;
            ms += m.coeffs[i] & 2;
        }

        t |= ps ^ (ms >>> 1);
        t |= ms ^ ((NTRUHPSParameterSet)params).weight();

        /* We have 0 <= t < 2^16. */
        /* Return 0 on success (t=0), 1 on failure */
        return (1 & ((~t + 1) >>> 31));
    }
}
