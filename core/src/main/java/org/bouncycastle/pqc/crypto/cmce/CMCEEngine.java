package org.bouncycastle.pqc.crypto.cmce;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

class CMCEEngine
{
    private int SYS_N;       // = 3488;
    private int SYS_T;       // = 64;
    private int GFBITS;      // = 12;

    private int IRR_BYTES;   // = SYS_T * 2;
    private int COND_BYTES;  // = (1 << (GFBITS-4))*(2*GFBITS - 1);


    private int PK_NROWS;    // = SYS_T*GFBITS;
    private int PK_NCOLS;    // = SYS_N - PK_NROWS;
    private int PK_ROW_BYTES;// = (PK_NCOLS + 7)/8;

    private int SYND_BYTES;// = (PK_NROWS + 7)/8;

    private int GFMASK;    // = (1 << GFBITS) - 1;

    private int[] poly; // only needed for key pair gen
    private final int defaultKeySize;

    private GF gf;
    private BENES benes;

    private boolean usePadding;
    private boolean countErrorIndices;
    private boolean usePivots; // used for compression

    public int getIrrBytes()
    {
        return IRR_BYTES;
    }

    public int getCondBytes()
    {
        return COND_BYTES;
    }

    public int getPrivateKeySize()
    {
        return COND_BYTES + IRR_BYTES + SYS_N / 8 + 40;
    }

    public int getPublicKeySize()
    {
        if (usePadding)
        {
            return PK_NROWS * ((SYS_N / 8 - ((PK_NROWS - 1) / 8)));
        }
        return PK_NROWS * PK_NCOLS / 8;
    }

    //    public int getPublicKeySize(){ return PK_NCOLS*PK_NROWS/8; }
    public int getCipherTextSize()
    {
        return SYND_BYTES;
    }

    public CMCEEngine(int m, int n, int t, int[] p, boolean usePivots, int defaultKeySize)
    {
        this.usePivots = usePivots;
        this.SYS_N = n;
        this.SYS_T = t;
        this.GFBITS = m;
        this.poly = p;
        this.defaultKeySize = defaultKeySize;

        IRR_BYTES = SYS_T * 2; // t * ceil(m/8)
        COND_BYTES = (1 << (GFBITS - 4)) * (2 * GFBITS - 1);

        PK_NROWS = SYS_T * GFBITS;
        PK_NCOLS = SYS_N - PK_NROWS;
        PK_ROW_BYTES = (PK_NCOLS + 7) / 8;

        SYND_BYTES = (PK_NROWS + 7) / 8;
        GFMASK = (1 << GFBITS) - 1;

        if (GFBITS == 12)
        {
            gf = new GF12();
            benes = new BENES12(SYS_N, SYS_T, GFBITS);
        }
        else
        {
            gf = new GF13();
            benes = new BENES13(SYS_N, SYS_T, GFBITS);
        }

        usePadding = SYS_T % 8 != 0;
        countErrorIndices = (1 << GFBITS) > SYS_N;
    }
    public byte[] generate_public_key_from_private_key(byte[] sk)
    {
        byte[] pk = new byte[getPublicKeySize()];
        short[] pi = new short[1 << GFBITS];
        long[] pivots = {0};

        // generating the perm used to generate the private key
        int[] perm = new int[1 << GFBITS];
        byte[] hash = new byte[(SYS_N / 8) + ((1 << GFBITS) * 4)];
        int hash_idx = hash.length - 32 - IRR_BYTES - ((1 << GFBITS) * 4);

        Xof digest;
        digest = new SHAKEDigest(256);
        digest.update((byte)64);
        digest.update(sk, 0, 32);
        digest.doFinal(hash, 0, hash.length);

        for (int i = 0; i < (1 << GFBITS); i++)
        {
            perm[i] = Utils.load4(hash, hash_idx + i * 4);
        }
        pk_gen(pk, sk, perm, pi, pivots);
        return pk;
    }

    // generates the rest of the private key given the first 40 bytes
    public byte[] decompress_private_key(byte[] sk)
    {
        byte[] reg_sk = new byte[getPrivateKeySize()];
        System.arraycopy(sk, 0, reg_sk, 0, sk.length);

        // s: n/8 (random string)
        // a: COND_BYTES (field ordering) ((2m-1) * 2^(m-4))
        // g: IRR_BYTES (polynomial) (t * 2)

        // generate hash using the seed given in the sk (64 || first 32 bytes)
        byte[] hash = new byte[(SYS_N / 8) + ((1 << GFBITS) * 4) + IRR_BYTES + 32];

        int hash_idx = 0;
        Xof digest;
        digest = new SHAKEDigest(256);
        digest.update((byte)64);
        digest.update(sk, 0, 32); // input
        digest.doFinal(hash, 0, hash.length);


        // generate g
        if (sk.length <= 40)
        {
            short[] field = new short[SYS_T];

            byte[] reg_g = new byte[IRR_BYTES];
            hash_idx = hash.length - 32 - IRR_BYTES;
            for (int i = 0; i < SYS_T; i++)
            {
                field[i] = Utils.load_gf(hash, hash_idx + i * 2, GFMASK);
            }
            generate_irr_poly(field);

            for (int i = 0; i < SYS_T; i++)
            {
                Utils.store_gf(reg_g, i * 2, field[i]);
            }
            System.arraycopy(reg_g, 0, reg_sk, 40, IRR_BYTES);
        }

        // generate a
        if (sk.length <= 40 + IRR_BYTES)
        {
            int[] perm = new int[1 << GFBITS];
            short[] pi = new short[1 << GFBITS];

            hash_idx = hash.length - 32 - IRR_BYTES - ((1 << GFBITS) * 4);
            for (int i = 0; i < (1 << GFBITS); i++)
            {
                perm[i] = Utils.load4(hash, hash_idx + i * 4);
            }

            if (usePivots)
            {
                long[] pivots = {0};
                pk_gen(null, reg_sk, perm, pi, pivots);
            }
            else
            {
                long[] buf = new long[1 << GFBITS];
                for (int i = 0; i < (1 << GFBITS); i++)
                {
                    buf[i] = perm[i];
                    buf[i] <<= 31;
                    buf[i] |= i;
                    buf[i] &= 0x7fffffffffffffffL; // getting rid of signed longs
                }
                sort64(buf, 0, buf.length);
                for (int i = 0; i < (1 << GFBITS); i++)
                {
                    pi[i] = (short)(buf[i] & GFMASK);
                }
            }


            byte[] out = new byte[COND_BYTES];
            controlbitsfrompermutation(out, pi, GFBITS, 1 << GFBITS);
            //copy the controlbits from the permutation to the private key
            System.arraycopy(out, 0, reg_sk, IRR_BYTES + 40, out.length);
        }

        // reg s
        System.arraycopy(hash, 0, reg_sk, getPrivateKeySize() - SYS_N / 8, SYS_N / 8);
        return reg_sk;
    }

    public void kem_keypair(byte[] pk, byte[] sk, SecureRandom random)
    {

        // 1. Generate a uniform random l-bit string δ. (This is called a seed.)
        byte[] seed_a = new byte[1];
        byte[] seed_b = new byte[32];
        seed_a[0] = 64;
        random.nextBytes(seed_b);

        //2. Output SeededKeyGen(δ).
        // SeededKeyGen
        byte[] E = new byte[(SYS_N / 8) + ((1 << GFBITS) * 4) + (SYS_T * 2) + 32];
        int seedIndex, skIndex = 0;
        byte[] prev_sk = seed_b;
        long[] pivots = {0};

        Xof digest = new SHAKEDigest(256);
        while (true)
        {
            // SeededKeyGen - 1. Compute E = G(δ), a string of n + σ2q + σ1t + l bits. (3488 + 32*4096 + 16*64 + 256)
            digest.update(seed_a, 0, seed_a.length);
            digest.update(seed_b, 0, seed_b.length);
            digest.doFinal(E, 0, E.length);
            // Store the seeds generated

            // SeededKeyGen - 2. Define δ′ as the last l bits of E.
            // Update seed using the last 32 bytes (l) of E
            // If anything fails, this set δ = δ′ (the next last 32 bytes of E) and restart the algorithm.
            seedIndex = E.length - 32;
            seed_b = Arrays.copyOfRange(E, seedIndex, seedIndex + 32);

            // store the previous last 32 bytes used as δ
            System.arraycopy(prev_sk, 0, sk, 0, 32);
            prev_sk = Arrays.copyOfRange(seed_b, 0, 32);

            // (step 5 and 4 are swapped)
            // SeededKeyGen - 5. Compute g from the next σ1t bits of E by the Irreducible algorithm. If this fails,
            // set δ = δ′ and restart the algorithm.

            // Create Field which is an element in gf2^mt

            // 2.4.1 Irreducible-polynomial generation
            short[] field = new short[SYS_T];
            int sigma1_t = E.length - 32 - (2 * SYS_T);
            seedIndex = sigma1_t;


            // Irreducible 2.4.1 - 1. Define βj = ∑m−1
            // i=0 dσ1j+izi for each j ∈ {0,1,...,t −1}. (Within each group of σ1
            // input bits, this uses only the first m bits.
            for (int i = 0; i < SYS_T; i++)
            {
                field[i] = Utils.load_gf(E, sigma1_t + i * 2, GFMASK);
            }

            if (generate_irr_poly(field) == -1)
            {
                continue;
            }

            // storing poly to sk
            skIndex = 32 + 8;
            for (int i = 0; i < SYS_T; i++)
            {
                Utils.store_gf(sk, skIndex + i * 2, field[i]);
            }

            // SeededKeyGen - 4. Compute α1,...,αq from the next σ2q bits of E by the FieldOrdering algorithm.
            // If this fails, set δ = δ′ and restart the algorithm.

            // Generate permutation
            int[] perm = new int[(1 << GFBITS)];
            seedIndex -= (1 << GFBITS) * 4;

            // FieldOrdering 2.4.2 - 1. Take the first σ2 input bits b0,b1,...,bσ2−1 as a σ2-bit integer a0 =
            // b0 + 2b1 + ··· + 2σ2−1bσ2−1, take the next σ2 bits as a σ2-bit integer a1, and so on through aq−1.


            for (int i = 0; i < (1 << GFBITS); i++)
            {
                perm[i] = Utils.load4(E, seedIndex + i * 4);
            }
            // generating public key
            short[] pi = new short[1 << GFBITS];


            //8. Write Γ′ as (g,α′1,α′2,...,α′n)
            if (pk_gen(pk, sk, perm, pi, pivots) == -1)
            {
//                System.out.println("FAILED GENERATING PUBLIC KEY");
                continue;
            }

            // computing c using Nassimi-Sahni algorithm which is a
            // parallel algorithms to set up the Benes permutation network

            byte[] out = new byte[COND_BYTES];
            controlbitsfrompermutation(out, pi, GFBITS, 1 << GFBITS);

            //copy the controlbits from the permutation to the private key
            System.arraycopy(out, 0, sk, IRR_BYTES + 40, out.length);

            // storing the random string s
            seedIndex -= SYS_N / 8;
            System.arraycopy(E, seedIndex, sk, sk.length - SYS_N / 8, SYS_N / 8);

            // This part is reserved for compression which is not implemented and is not required
            if (!usePivots)
            {
                Utils.store8(sk, 32, 0xFFFFFFFFL);
            }
            else
            {
                Utils.store8(sk, 32, pivots[0]);
            }

            // 9. Output T as public key and (δ,c,g,α,s) as private key, where c = (cn−k−μ+1,...,cn−k)
            // and α = (α′1,...,α′n,αn+1,...,αq
            break;
        }
    }

    // 2.2.3 Encoding subroutine
    private void syndrome(byte[] cipher_text, byte[] pk, byte[] error_vector)
    {
        /*
        2.2.3 Encoding subroutine
        1. Define H = (In−k |T)
        2. Compute and return C0 = He ∈Fn−k2 .
         */
        short[] row = new short[SYS_N / 8];
        int i, j, pk_ptr = 0;
        byte b;
        int tail = PK_NROWS % 8;

        for (i = 0; i < SYND_BYTES; i++)
        {
            cipher_text[i] = 0;
        }

        for (i = 0; i < PK_NROWS; i++)
        {
            for (j = 0; j < SYS_N / 8; j++)
            {
                row[j] = 0;
            }

            for (j = 0; j < PK_ROW_BYTES; j++)
            {
                row[SYS_N / 8 - PK_ROW_BYTES + j] = pk[pk_ptr + j];
            }
            if (usePadding)
            {
                for (j = SYS_N / 8 - 1; j >= SYS_N / 8 - PK_ROW_BYTES; j--)
                {
                    row[j] = (short)((((row[j] & 0xff) << tail) | ((row[j - 1] & 0xff) >>> (8 - tail))) & 0xff);
//                    System.out.printf("%04x ", row[j]);
                }
            }


            row[i / 8] |= 1 << (i % 8);

            b = 0;
            for (j = 0; j < SYS_N / 8; j++)
            {
                b ^= row[j] & error_vector[j];
            }

            b ^= b >>> 4;
            b ^= b >>> 2;
            b ^= b >>> 1;
            b &= 1;

            cipher_text[i / 8] |= (b << (i % 8));

            pk_ptr += PK_ROW_BYTES;
        }
    }

    // 2.4.4 Fixed-weight-vector generation
    private void generate_error_vector(byte[] error_vector, SecureRandom random)
    {
        byte[] buf_bytes;
        short[] buf_nums = new short[SYS_T * 2];
        short[] ind = new short[SYS_T];
        byte[] val = new byte[SYS_T];

        /*
        2.4.4 Fixed-weight-vector generation
        1. Generate σ1τ uniform random bits b0,b1,...,bσ1τ−1.
         */
        while (true)
        {

            /*
            2.4.4 Fixed-weight-vector generation
            2. Define dj = ∑m−1
            i=0 bσ1j+i2i for each j ∈{0,1,...,τ −1}.
             */
            if (countErrorIndices)
            {
                buf_bytes = new byte[SYS_T * 4];

                random.nextBytes(buf_bytes);
                for (int i = 0; i < SYS_T * 2; i++)
                {
                    buf_nums[i] = Utils.load_gf(buf_bytes, i * 2, GFMASK);
                }

            /*
            2.4.4 Fixed-weight-vector generation
            3. Define a0,a1,...,at−1 as the first t entries in d0,d1,...,dτ−1 in the range
            {0,1,...,n −1}. If there are fewer than t such entries, restart the algorithm
             */

                // moving and counting indices in the correct range
                int count = 0;
                for (int i = 0; i < SYS_T * 2 && count < SYS_T; i++)
                {
                    if (buf_nums[i] < SYS_N)
                    {
                        ind[count++] = buf_nums[i];
                    }
                }

                if (count < SYS_T)
                {
//                System.out.println("Failed Encrypt indices wrong range");
                    continue;
                }
            }
            else
            {
                buf_bytes = new byte[SYS_T * 2];
                random.nextBytes(buf_bytes);

                for (int i = 0; i < SYS_T; i++)
                {
                    ind[i] = Utils.load_gf(buf_bytes, i * 2, GFMASK);
                }
            }


            /*
            2.4.4 Fixed-weight-vector generation
            4. If a0,a1,...,at−1 are not all distinct, restart the algorithm.
             */
            int eq = 0;
            // check for repetition
            for (int i = 1; i < SYS_T && eq != 1; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    if (ind[i] == ind[j])
                    {
                        eq = 1;
                        break;
                    }
                }
            }

            if (eq == 0)
            {
                break;
            }
            else
            {
//                System.out.println("Failed Encrypt found duplicate");
            }
        }


        /*
        2.4.4 Fixed-weight-vector generation
        5. Define e = (e0,e1,...,en−1) ∈ Fn2 as the weight-t vector such that eai = 1 for each i.
        (Implementors are cautioned to compute e through arithmetic rather than variable-
        time RAM lookups.)
         */
        for (int i = 0; i < SYS_T; i++)
        {
            val[i] = (byte)(1 << (ind[i] & 7));
        }
//        System.out.print("e: ");
        for (short i = 0; i < SYS_N / 8; i++)
        {
            error_vector[i] = 0;

            for (int j = 0; j < SYS_T; j++)
            {
                short mask = same_mask32(i, (short)(ind[j] >> 3));
                mask &= 0xff;
                error_vector[i] |= val[j] & mask;
//                System.out.printf("%02x ", mask);
            }
        }
    }

    private void encrypt(byte[] cipher_text, byte[] pk, byte[] error_vector, SecureRandom random)
    {
        /*
        2.4.5 Encapsulation
        1. Use FixedWeight to generate a vector e ∈Fn2 of weight t.
         */

        // 2.4.4 Fixed-weight-vector generation
        generate_error_vector(error_vector, random);

        /*
        2.4.5 Encapsulation
        2. Compute C0 = Encode(e,T).
         */
        syndrome(cipher_text, pk, error_vector);
    }

    // 2.4.5 Encapsulation
    public int kem_enc(byte[] cipher_text, byte[] key, byte[] pk, SecureRandom random)
    {
        byte[] error_vector = new byte[SYS_N / 8];
        byte mask;
        int i, padding_ok = 0;
        if (usePadding)
        {
            padding_ok = check_pk_padding(pk);
//            System.out.println("padding_ok: " + padding_ok);
        }

        /*
        2.4.5 Encapsulation
        1. Use FixedWeight to generate a vector e ∈Fn2 of weight t.
        2. Compute C0 = Encode(e,T).
         */
        encrypt(cipher_text, pk, error_vector, random);

        /*
        2.4.5 Encapsulation
        4. Compute K = H(1,e,C)
         */

        // K = Hash((0x1 || e || C), 32)
        Xof digest = new SHAKEDigest(256);
        digest.update((byte)0x01);
        digest.update(error_vector, 0, error_vector.length);
        digest.update(cipher_text, 0, cipher_text.length); // input
        digest.doFinal(key, 0, key.length);     // output

        if (usePadding)
        {
            //
            // clear outputs (set to all 0's) if padding bits are not all zero
            mask = (byte)padding_ok;
            mask ^= 0xFF;

            for (i = 0; i < SYND_BYTES; i++)
            {
                cipher_text[i] &= mask;
            }

            for (i = 0; i < 32; i++)
            {
                key[i] &= mask;
            }

            return padding_ok;
        }
        return 0;
    }

    // 2.3.3 Decapsulation
    public int kem_dec(byte[] key, byte[] cipher_text, byte[] sk)
    {
        byte[] error_vector = new byte[SYS_N / 8];
        byte[] preimage = new byte[1 + SYS_N/8 + SYND_BYTES];

        int i, padding_ok = 0;
        byte mask;
        if (usePadding)
        {
            padding_ok = check_c_padding(cipher_text);
        }

        /*
        2.3.3 Decapsulation
        4. Compute e = Decode(C0,Γ′). If e = ⊥, set e = s and b = 0.
         */

        // Decrypt
        byte ret_decrypt = (byte)decrypt(error_vector, sk, cipher_text);

        /*
        2.3.3 Decapsulation
        6. If C′1 6= C1, set e = s and b = 0.
         */

        short m;
        m = ret_decrypt;
        m -= 1;
        m >>= 8;
        m &= 0xff;

        /*
        2.3.3 Decapsulation
        2. Set b = 1.
         */
        preimage[0] = (byte)(m & 1);
        for (i = 0; i < SYS_N / 8; i++)
        {
            preimage[1 + i] = (byte)((~m & sk[i + 40 + IRR_BYTES + COND_BYTES]) | (m & error_vector[i]));
        }
        for (i = 0; i < SYND_BYTES; i++)
        {
            preimage[1 + SYS_N / 8 + i] = cipher_text[i];
        }

        /*
        2.3.3 Decapsulation
        7. Compute K = H(b,e,C)
         */

        //  = SHAKE256(preimage, 32)
        Xof digest = new SHAKEDigest(256);
        digest.update(preimage, 0, preimage.length); // input
        digest.doFinal(key, 0, key.length);     // output


        // clear outputs (set to all 1's) if padding bits are not all zero
        if (usePadding)
        {
            mask = (byte)padding_ok;

            for (i = 0; i < key.length; i++)
            {
                key[i] |= mask;
            }

            return padding_ok;
        }
        return 0;
    }

    // 2.2.4 Decoding subroutine
    // Niederreiter decryption with the Berlekamp decoder
    private int decrypt(byte[] error_vector, byte[] sk, byte[] cipher_text)
    {

        short[] g = new short[SYS_T + 1];
        short[] L = new short[SYS_N];

        short[] s = new short[SYS_T * 2];
        short[] s_cmp = new short[SYS_T * 2];
        short[] locator = new short[SYS_T + 1];
        short[] images = new short[SYS_N];

        short t;

        byte[] r = new byte[SYS_N / 8];

        /*
        2.2.4 Decoding subroutine
        1. Extend C0 to v = (C0,0,...,0) ∈Fn2 by appending k zeros.
         */
        for (int i = 0; i < SYND_BYTES; i++)
        {
            r[i] = cipher_text[i];
        }

        for (int i = SYND_BYTES; i < SYS_N / 8; i++)
        {
            r[i] = 0;
        }

        for (int i = 0; i < SYS_T; i++)
        {
            g[i] = Utils.load_gf(sk, 40 + i * 2, GFMASK);
        }
        g[SYS_T] = 1;

        /*
        2.2.4 Decoding subroutine
        2. Find the unique codeword c in the Goppa code defined by Γ′ that is at distance ≤t
        from v. If there is no such codeword, return ⊥.
         */

        // support gen
        benes.support_gen(L, sk);

        // compute syndrome
        synd(s, g, L, r);

        // compute minimal polynomial of syndrome
        bm(locator, s);

        // calculate the root for locator in L
        root(images, locator, L);


        /*
        2.2.4 Decoding subroutine
        3. Set e = v + c.
         */
        for (int i = 0; i < SYS_N / 8; i++)
        {
            error_vector[i] = 0;
        }

        int w = 0;
        for (int i = 0; i < SYS_N; i++)
        {
            t = (short)(gf.gf_iszero(images[i]) & 1);

            error_vector[i / 8] |= t << (i % 8);
            w += t;
        }

        // compute syndrome
        synd(s_cmp, g, L, error_vector);

        /*
        2.2.4 Decoding subroutine
        4. If wt(e) = t and C0 = He, return e. Otherwise return ⊥
         */
        int check;
        check = w;
        check ^= SYS_T;

        for (int i = 0; i < SYS_T * 2; i++)
        {
            check |= s[i] ^ s_cmp[i];
        }
        check -= 1;
        check >>= 15;
        check &= 0x1;
        if ((check ^ 1) != 0)
        {
            //TODO throw exception?
//            System.out.println("Decryption failed");
        }
        return check ^ 1;
    }

    private static int min(short a, int b)
    {
        if (a < b)
        {
            return a;
        }
        return b;
    }

    /* the Berlekamp-Massey algorithm */
    /* input: s, sequence of field elements */
    /* output: out, minimal polynomial of s */
    private void bm(short[] out, short[] s)
    {
        short N = 0;
        short L = 0;
        short mle;
        short mne;

        short[] T = new short[SYS_T + 1];
        short[] C = new short[SYS_T + 1];
        short[] B = new short[SYS_T + 1];

        short b = 1, d, f;
        //

        for (int i = 0; i < SYS_T + 1; i++)
        {
            C[i] = B[i] = 0;
        }

        B[1] = C[0] = 1;

        //

        for (N = 0; N < 2 * SYS_T; N++)
        {
            int d_ext = 0;
            for (int i = 0; i <= min(N, SYS_T); i++)
            {
                d_ext ^= gf.gf_mul_ext(C[i], s[N - i]);
            }

            d = gf.gf_reduce(d_ext);

            mne = d;
            mne -= 1;
            mne >>= 15;
            mne &= 0x1;
            mne -= 1;
            mle = N;
            mle -= 2 * L;
            mle >>= 15;
            mle &= 0x1;
            mle -= 1;
            mle &= mne;

            for (int i = 0; i <= SYS_T; i++)
            {
                T[i] = C[i];
            }

            f = gf.gf_frac(b, d);

            for (int i = 0; i <= SYS_T; i++)
            {
                C[i] ^= gf.gf_mul(f, B[i]) & mne;
            }
            L = (short)((L & ~mle) | ((N + 1 - L) & mle));

            for (int i = SYS_T - 1; i >= 0; i--)
            {
                B[i + 1] = (short)((B[i] & ~mle) | (T[i] & mle));
            }
            B[0] = 0;

            b = (short)((b & ~mle) | (d & mle));
        }

        for (int i = 0; i <= SYS_T; i++)
        {
            out[i] = C[SYS_T - i];
        }
    }

    /* input: Goppa polynomial f, support L, received word r */
    /* output: out, the syndrome of length 2t */
    private void synd(short[] out, short[] f, short[] L, byte[] r)
    {
        {
            short c = (short)(r[0] & 1);

            short L_i = L[0];
            short e = eval(f, L_i);
            short e_inv = gf.gf_inv(gf.gf_sq(e));
            short c_div_e = (short)(e_inv & -c);

            out[0] = c_div_e;

            for (int j = 1; j < 2 * SYS_T; j++)
            {
                c_div_e = gf.gf_mul(c_div_e, L_i);
                out[j] = c_div_e;
            }
        }
        for (int i = 1; i < SYS_N; i++)
        {
            short c = (short)((r[i / 8] >> (i % 8)) & 1);

            short L_i = L[i];
            short e = eval(f, L_i);
            short e_inv = gf.gf_inv(gf.gf_sq(e));
            short c_div_e = gf.gf_mul(e_inv, c);

            out[0] ^= c_div_e;

            for (int j = 1; j < 2 * SYS_T; j++)
            {
                c_div_e = gf.gf_mul(c_div_e, L_i);
                out[j] ^= c_div_e;
            }
        }
    }

    private int mov_columns(byte[][] mat, short[] pi, long[] pivots)
    {
        int i, j, k, s, block_idx, row, tail;
        long[] buf = new long[64],
            ctz_list = new long[32];
        long t, d, mask, one = 1;

        byte[] tmp = new byte[9]; // Used for padding

        row = PK_NROWS - 32;
        block_idx = row / 8;
        tail = row % 8;

        // extract the 32x64 matrix
        if (usePadding)
        {
            for (i = 0; i < 32; i++)
            {
                for (j = 0; j < 9; j++)
                {
                    tmp[j] = mat[row + i][block_idx + j];
                }
                for (j = 0; j < 8; j++)
                {
                    tmp[j] = (byte)(((tmp[j] & 0xff) >> tail) | (tmp[j + 1] << (8 - tail)));
                }

                buf[i] = Utils.load8(tmp, 0);
            }
        }
        else
        {
            for (i = 0; i < 32; i++)
            {
                buf[i] = Utils.load8(mat[row + i], block_idx);
            }
        }


        // compute the column indices of pivots by Gaussian elimination.
        // the indices are stored in ctz_list

        pivots[0] = 0;

        for (i = 0; i < 32; i++)
        {
            t = buf[i];
            for (j = i + 1; j < 32; j++)
            {
                t |= buf[j];
            }

            if (t == 0)
            {
                return -1; // return if buf is not full rank
            }

            ctz_list[i] = s = ctz(t);
            pivots[0] |= one << ctz_list[i];

            for (j = i + 1; j < 32; j++)
            {
                mask = (buf[i] >> s) & 1;
                mask -= 1;
                buf[i] ^= buf[j] & mask;
            }
            for (j = i + 1; j < 32; j++)
            {
                mask = (buf[j] >> s) & 1;
                mask = -mask;
                buf[j] ^= buf[i] & mask;
            }
        }

        // updating permutation

        for (j = 0; j < 32; j++)
        {
            for (k = j + 1; k < 64; k++)
            {
                d = pi[row + j] ^ pi[row + k];
                d &= same_mask64((short)k, (short)ctz_list[j]);
                pi[row + j] ^= d;
                pi[row + k] ^= d;
            }
        }

        // moving columns of mat according to the column indices of pivots

        for (i = 0; i < PK_NROWS; i++)
        {
            if (usePadding)
            {
                for (k = 0; k < 9; k++)
                {
                    tmp[k] = mat[i][block_idx + k];
                }
                for (k = 0; k < 8; k++)
                {
                    tmp[k] = (byte)(((tmp[k] & 0xff) >> tail) | (tmp[k + 1] << (8 - tail)));
                }
                t = Utils.load8(tmp, 0);
            }
            else
            {
                t = Utils.load8(mat[i], block_idx);
            }

            for (j = 0; j < 32; j++)
            {
                d = t >> j;
                d ^= t >> ctz_list[j];
                d &= 1;

                t ^= d << ctz_list[j];
                t ^= d << j;
            }
            if (usePadding)
            {
                Utils.store8(tmp, 0, t);

                mat[i][block_idx + 8] = (byte)(((mat[i][block_idx + 8] & 0xff) >>> tail << tail) | ((tmp[7] & 0xff) >>> (8 - tail)));
                mat[i][block_idx + 0] = (byte)(((tmp[0] & 0xff) << tail) | ((mat[i][block_idx] & 0xff) << (8 - tail) >>> (8 - tail)));

                for (k = 7; k >= 1; k--)
                {
                    mat[i][block_idx + k] = (byte)(((tmp[k] & 0xff) << tail) | ((tmp[k - 1] & 0xff) >>> (8 - tail)));
                }
            }
            else
            {
                Utils.store8(mat[i], block_idx, t);
            }
        }

        return 0;
    }

    /* return number of trailing zeros of the non-zero input in */
    private static int ctz(long in)
    {
//        int i, b, m = 0, r = 0;
//
//        for (i = 0; i < 64; i++)
//        {
//            b = (int)((in >> i) & 1);
//            m |= b;
//            r += (m ^ 1) & (b ^ 1);
//        }
//
//        return r;

        long m1 = 0x0101010101010101L, r8 = 0, x = ~in;
        for (int i = 0; i < 8; ++i)
        {
            m1 &= x >>> i;
            r8 += m1;
        }

        long m8 = r8 & 0x0808080808080808L;
        m8 |= m8 >>> 1;
        m8 |= m8 >>> 2;

        long r = r8;
        r8 >>>= 8;
        r += r8 & m8;
        for (int i = 2; i < 8; ++i)
        {
            m8 &= m8 >>> 8;
            r8 >>>= 8;
            r += r8 & m8;
        }
        return (int)r & 0xFF;
    }

    /* Used in mov columns*/
    static private long same_mask64(short x, short y)
    {
        long mask;

        mask = x ^ y;
        mask -= 1;
        mask >>>= 63;
        mask = -mask;

        return mask;
    }

    /* Used in error vector generation*/
    private static byte same_mask32(short x, short y)
    {
        int mask;

        mask = x ^ y;
        mask -= 1;
        mask >>>= 31;
        mask = -mask;
        return (byte)(mask & 0xFF);
    }

    private static void layer(short[] p, byte[] out, int ptrIndex, int s, int n)
    {
        int i, j;
        int stride = 1 << s;
        int index = 0;
        int d, m;

        for (i = 0; i < n; i += stride * 2)
        {
            for (j = 0; j < stride; j++)
            {
                d = p[i + j] ^ p[i + j + stride];
                m = (out[ptrIndex + (index >> 3)] >> (index & 7)) & 1;
                m = -m;
                d &= m;
                p[i + j] ^= d;
                p[i + j + stride] ^= d;
                index++;
            }
        }
    }

    private static void controlbitsfrompermutation(byte[] out, short[] pi, long w, long n)
    {
        int[] temp = new int[(int)(2 * n)];
        short[] pi_test = new short[(int)n];
        short diff;
        int i;
        int ptrIndex;
        while (true)
        {
            for (i = 0; i < (((2 * w - 1) * n / 2) + 7) / 8; i++)
            {
                out[i] = 0;
            }
            cbrecursion(out, 0, 1, pi, 0, w, n, temp);

            // check for correctness
            for (i = 0; i < n; i++)
            {
                pi_test[i] = (short)i;
            }

            ptrIndex = 0;
            for (i = 0; i < w; i++)
            {
                layer(pi_test, out, ptrIndex, i, (int)n);
                ptrIndex += n >> 4;
            }

            for (i = (int)(w - 2); i >= 0; i--)
            {
                layer(pi_test, out, ptrIndex, i, (int)n);
                ptrIndex += n >> 4;
            }

            diff = 0;
            for (i = 0; i < n; i++)
            {
                diff |= pi[i] ^ pi_test[i];
            }

            if (diff == 0)
            {
                break;
            }
        }
    }

    static short get_q_short(int[] temp, int q_index)
    {
        int temp_index = q_index / 2;
        if (q_index % 2 == 0)
        {
            return (short)temp[temp_index];
        }
        else
        {
            return (short)((temp[temp_index] & 0xffff0000) >> 16);
        }
    }

    static void cbrecursion(byte[] out, long pos, long step, short[] pi, int qIndex, long w, long n, int[] temp)
    {
        long x, i, j, k;

        if (w == 1)
        {
            out[(int)(pos >> 3)] ^= get_q_short(temp, qIndex) << (pos & 7);
            return;
        }

        if (pi != null)
        {
            for (x = 0; x < n; ++x)
            {
                temp[(int)x] = ((pi[(int)x] ^ 1) << 16) | pi[(int)(x ^ 1)];
            }
        }
        else
        {
            for (x = 0; x < n; ++x)
            {
                temp[(int)x] = ((get_q_short(temp, (int)(qIndex + x)) ^ 1) << 16) | get_q_short(temp, (int)((qIndex) + (x ^ 1)));
            }
        }
        sort32(temp, 0, (int)n); /* A = (id<<16)+pibar */

        for (x = 0; x < n; ++x)
        {
            int Ax = temp[(int)x];
            int px = Ax & 0xffff;
            int cx = px;
            if (x < cx)
            {
                cx = (int)x;
            }
            temp[(int)(n + x)] = (px << 16) | cx;
        }

        for (x = 0; x < n; ++x)
        {
            temp[(int)x] = (int)((temp[(int)x] << 16) | x); /* A = (pibar<<16)+id */
        }
        sort32(temp, 0, (int)n); /* A = (id<<16)+pibar^-1 */

        for (x = 0; x < n; ++x)
        {
            temp[(int)x] = (temp[(int)x] << 16) + (temp[(int)(n + x)] >> 16); /* A = (pibar^(-1)<<16)+pibar */
        }
        sort32(temp, 0, (int)n); /* A = (id<<16)+pibar^2 */

        if (w <= 10)
        {
            for (x = 0; x < n; ++x)
            {
                temp[(int)(n + x)] = ((temp[(int)x] & 0xffff) << 10) | (temp[(int)(n + x)] & 0x3ff);
            }

            for (i = 1; i < w - 1; ++i)
            {
                /* B = (p<<10)+c */

                for (x = 0; x < n; ++x)
                {
                    temp[(int)x] = (int)(((temp[(int)(n + x)] & ~0x3ff) << 6) | x); /* A = (p<<16)+id */
                }
                sort32(temp, 0, (int)n); /* A = (id<<16)+p^{-1} */

                for (x = 0; x < n; ++x)
                {
                    temp[(int)x] = (temp[(int)x] << 20) | temp[(int)(n + x)]; /* A = (p^{-1}<<20)+(p<<10)+c */
                }
                sort32(temp, 0, (int)n); /* A = (id<<20)+(pp<<10)+cp */

                for (x = 0; x < n; ++x)
                {
                    int ppcpx = temp[(int)x] & 0xfffff;
                    int ppcx = (temp[(int)x] & 0xffc00) | (temp[(int)(n + x)] & 0x3ff);
                    if (ppcpx < ppcx)
                    {
                        ppcx = ppcpx;
                    }
                    temp[(int)(n + x)] = ppcx;
                }
            }
            for (x = 0; x < n; ++x)
            {
                temp[(int)(n + x)] &= 0x3ff;
            }
        }
        else
        {
            for (x = 0; x < n; ++x)
            {
                temp[(int)(n + x)] = (temp[(int)x] << 16) | (temp[(int)(n + x)] & 0xffff);
            }
            for (i = 1; i < w - 1; ++i)
            {
                /* B = (p<<16)+c */
                for (x = 0; x < n; ++x)
                {
                    temp[(int)x] = (int)((temp[(int)(n + x)] & ~0xffff) | x);
                }
                sort32(temp, 0, (int)n); /* A = (id<<16)+p^(-1) */
                for (x = 0; x < n; ++x)
                {
                    temp[(int)x] = (temp[(int)x] << 16) | (temp[(int)(n + x)] & 0xffff);
                }

                /* A = p^(-1)<<16+c */
                if (i < w - 2)
                {
                    //if loop 1 B
                    for (x = 0; x < n; ++x)
                    {
                        temp[(int)(n + x)] = (temp[(int)x] & ~0xffff) | (temp[(int)(n + x)] >> 16);
                    }
                    /* B = (p^(-1)<<16)+p */

                    sort32(temp, (int)n, (int)(n * 2)); /* B = (id<<16)+p^(-2) */
                    for (x = 0; x < n; ++x)
                    {
                        temp[(int)(n + x)] = (temp[(int)(n + x)] << 16) | (temp[(int)x] & 0xffff);
                    }
                    /* B = (p^(-2)<<16)+c */
                }


                sort32(temp, 0, (int)n);
                /* A = id<<16+cp */
                for (x = 0; x < n; ++x)
                {
                    int cpx = (temp[(int)(n + x)] & ~0xffff) | (temp[(int)x] & 0xffff);
                    if (cpx < temp[(int)(n + x)])
                    {
                        temp[(int)(n + x)] = cpx;
                    }
                }
            }
            for (x = 0; x < n; ++x)
            {
                temp[(int)(n + x)] &= 0xffff;
            }
        }
        if (pi != null)
        {
            for (x = 0; x < n; ++x)
            {
                temp[(int)x] = (int)((((int)pi[(int)x]) << 16) + x);
            }
        }
        else
        {
            for (x = 0; x < n; ++x)
            {
                temp[(int)x] = (int)(((get_q_short(temp, (int)(qIndex + x))) << 16) + x);
            }
        }

        sort32(temp, 0, (int)n); /* A = (id<<16)+pi^(-1) */

        for (j = 0; j < n / 2; ++j)
        {
            long _x = 2 * j;
            int fj = temp[(int)(n + _x)] & 1; /* f[j] */
            int Fx = (int)(_x + fj); /* F[x] */
            int Fx1 = Fx ^ 1; /* F[x+1] */

            out[(int)(pos >> 3)] ^= fj << (pos & 7);
            pos += step;

            temp[(int)(n + _x)] = (temp[(int)_x] << 16) | Fx;
            temp[(int)(n + _x + 1)] = (temp[(int)(_x + 1)] << 16) | Fx1;
        }
        /* B = (pi^(-1)<<16)+F */

        sort32(temp, (int)n, (int)(n * 2)); /* B = (id<<16)+F(pi) */

        pos += (2 * w - 3) * step * (n / 2);

        for (k = 0; k < n / 2; ++k)
        {
            long y = 2 * k;
            int lk = temp[(int)(n + y)] & 1; /* l[k] */
            int Ly = (int)(y + lk); /* L[y] */
            int Ly1 = Ly ^ 1; /* L[y+1] */

            out[(int)(pos >> 3)] ^= lk << (pos & 7);
            pos += step;

            temp[(int)y] = (Ly << 16) | (temp[(int)(n + y)] & 0xffff);
            temp[(int)(y + 1)] = (Ly1 << 16) | (temp[(int)(n + y + 1)] & 0xffff);
        }
        /* A = (L<<16)+F(pi) */

        sort32(temp, 0, (int)n); /* A = (id<<16)+F(pi(L)) = (id<<16)+M */

        pos -= (2 * w - 2) * step * (n / 2);

        short[] q = new short[(int)n * 4];
        for (i = 0/*n + n/4*/; i < n * 2; i++)
        {
            q[(int)(i * 2 + 0)] = (short)temp[(int)i];
            q[(int)(i * 2 + 1)] = (short)((temp[(int)i] & 0xffff0000) >> 16);
        }
        for (j = 0; j < n / 2; ++j)
        {
            q[(int)j] = (short)((temp[(int)(2 * j)] & 0xffff) >>> 1);
            q[(int)(j + n / 2)] = (short)((temp[(int)(2 * j + 1)] & 0xffff) >>> 1);
        }
        for (i = 0; i < n / 2; i++)
        {
            temp[(int)(n + n / 4 + i)] = (((int)q[(int)(i * 2 + 1)]) << 16) | ((int)q[(int)(i * 2)]);
        }
        cbrecursion(out, pos, step * 2, null, (int)(n + n / 4) * 2, w - 1, n / 2, temp);
        cbrecursion(out, pos + step, step * 2, null, (int)((n + n / 4) * 2 + n / 2), w - 1, n / 2, temp);
    }

    private int pk_gen(byte[] pk, byte[] sk, int[] perm, short[] pi, long[] pivots)
    {
        short[] g = new short[SYS_T + 1]; // Goppa polynomial
        int i, j, k;
        g[SYS_T] = 1;

        for (i = 0; i < SYS_T; i++)
        {
            g[i] = Utils.load_gf(sk, 40 + i * 2, GFMASK);
        }

        // Create buffer
        long[] buf = new long[1 << GFBITS];
        for (i = 0; i < (1 << GFBITS); i++)
        {
            buf[i] = perm[i];
            buf[i] <<= 31;
            buf[i] |= i;
            buf[i] &= 0x7fffffffffffffffL; // getting rid of signed longs
        }
        // sort32 the buffer

        // FieldOrdering 2.4.2 - 3. sort32 the pairs (ai,i) in lexicographic order to obtain pairs (aπ(i),π(i))
        // where π is a permutation of {0,1,...,q −1}
        sort64(buf, 0, buf.length);

        // FieldOrdering 2.4.2 - 2. If a0,a1,...,aq−1 are not distinct, return ⊥.
        for (i = 1; i < (1 << GFBITS); i++)
        {
            if ((buf[i - 1] >> 31) == (buf[i] >> 31))
            {
//                System.out.println("FAIL 1");
                return -1;
            }
        }

        // FieldOrdering 2.4.2 - 4.
        short[] L = new short[SYS_N];
        for (i = 0; i < (1 << GFBITS); i++)
        {
            pi[i] = (short)(buf[i] & GFMASK);
        }
        for (i = 0; i < SYS_N; i++)
        {
            L[i] = Utils.bitrev(pi[i], GFBITS);
        }

        // filling matrix
        short[] inv = new short[SYS_N];

        root(inv, g, L);

        for (i = 0; i < SYS_N; i++)
        {
            inv[i] = gf.gf_inv(inv[i]);
        }
        byte[][] mat = new byte[PK_NROWS][(SYS_N / 8)];
        byte b;
        for (i = 0; i < PK_NROWS; i++)
        {
            for (j = 0; j < SYS_N / 8; j++)
            {
                mat[i][j] = 0;
            }
        }

        for (i = 0; i < SYS_T; i++)
        {
            for (j = 0; j < SYS_N; j += 8)
            {
                for (k = 0; k < GFBITS; k++)
                {
                    b = (byte)((inv[j + 7] >>> k) & 1);
                    b <<= 1;
                    b |= (inv[j + 6] >>> k) & 1;
                    b <<= 1;
                    b |= (inv[j + 5] >>> k) & 1;
                    b <<= 1;
                    b |= (inv[j + 4] >>> k) & 1;
                    b <<= 1;
                    b |= (inv[j + 3] >>> k) & 1;
                    b <<= 1;
                    b |= (inv[j + 2] >>> k) & 1;
                    b <<= 1;
                    b |= (inv[j + 1] >>> k) & 1;
                    b <<= 1;
                    b |= (inv[j + 0] >>> k) & 1;

                    mat[i * GFBITS + k][j / 8] = b;
                }
            }

            for (j = 0; j < SYS_N; j++)
            {
                inv[j] = gf.gf_mul(inv[j], L[j]);
            }
        }

        // gaussian elimination
        int row, c;
        byte mask;
        for (row = 0; row < PK_NROWS; row++)
        {
            i = row >>> 3;
            j = row & 7;

            if (usePivots)
            {
                if (row == PK_NROWS - 32)
                {
                    if (mov_columns(mat, pi, pivots) != 0)
                    {
//                        System.out.println("failed mov column!");
                        return -1;
                    }
                }
            }

            for (k = row + 1; k < PK_NROWS; k++)
            {
                mask = (byte)(mat[row][i] ^ mat[k][i]);
                mask >>= j;
                mask &= 1;
                mask = (byte)-mask;

                for (c = 0; c < SYS_N / 8; c++)
                {
                    mat[row][c] ^= mat[k][c] & mask;
                }
            }
            // 7. Compute (T,cn−k−μ+1,...,cn−k,Γ′) =  MatGen(Γ). If this fails, set δ =  δ′ and
            // restart the algorithm.
            if (((mat[row][i] >> j) & 1) == 0) // return if not systematic
            {
//                System.out.println("FAIL 2\n");
                return -1;
            }

            for (k = 0; k < PK_NROWS; k++)
            {
                if (k != row)
                {
                    mask = (byte)(mat[k][i] >> j);
                    mask &= 1;
                    mask = (byte)-mask;

                    for (c = 0; c < SYS_N / 8; c++)
                    {
                        mat[k][c] ^= mat[row][c] & mask;
                    }
                }
            }
        }

        // FieldOrdering 2.4.2 - 5. Output (α1,α2,...,αq)
        if (pk != null)
        {
            if (usePadding)
            {
                int pk_index = 0, tail = PK_NROWS % 8;
                if (tail == 0)
                {
                    System.arraycopy(mat[i], (PK_NROWS - 1) / 8, pk, pk_index, SYS_N / 8);
                    pk_index += SYS_N / 8;
                }
                else
                {
                    for (i = 0; i < PK_NROWS; i++)
                    {
                        for (j = (PK_NROWS - 1) / 8; j < SYS_N / 8 - 1; j++)
                        {
                            pk[pk_index++] = (byte)(((mat[i][j] & 0xff) >>> tail) | (mat[i][j + 1] << (8 - tail)));
                        }
                        pk[pk_index++] = (byte)((mat[i][j] & 0xff) >>> tail);
                    }
                }
            }
            else
            {
//                for (i = 0; i < PK_NROWS; i++)
//                {
//                    k = 0;
//                    for (j = 0; j < (((SYS_N - PK_NROWS) + 7) / 8); j++)
//                    {
//                        pk[i * (((SYS_N - PK_NROWS) + 7) / 8) + k] = mat[i][j + PK_NROWS / 8];
//                        k++;
//                    }
//                }
                int count = (SYS_N - PK_NROWS + 7) / 8;
                for (i = 0; i < PK_NROWS; i++)
                {
                    System.arraycopy(mat[i], PK_NROWS / 8, pk, count * i, count);
                }
            }
        }
        return 0;
    }


    private short eval(short[] f, short a)
    {
        short r = f[SYS_T];

        for (int i = SYS_T - 1; i >= 0; i--)
        {
            r = (short)(gf.gf_mul(r, a) ^ f[i]);
        }

        return r;
    }

    private void root(short[] out, short[] f, short[] L)
    {
        for (int i = 0; i < SYS_N; i++)
        {
            out[i] = eval(f, L[i]);
        }
    }

    private int generate_irr_poly(short[] field)
    {
        // Irreducible 2.4.1 - 2. Define β = β0 + β1y + ···+ βt−1yt−1 ∈Fq[y]/F(y).
        // generating poly
        short[][] m = new short[SYS_T + 1][SYS_T];

        // filling matrix
        {
            m[0][0] = 1;
//            for (int i = 1; i < SYS_T; i++)
//            {
//                m[0][i] = 0;
//            }

            System.arraycopy(field, 0, m[1], 0, SYS_T);

            int[] temp = new int[SYS_T * 2 - 1];
            int j = 2;
            while (j < SYS_T)
            {
                gf.gf_sqr_poly(SYS_T, poly, m[j], m[j >>> 1], temp);
                gf.gf_mul_poly(SYS_T, poly, m[j + 1], m[j], field, temp);
                j += 2;
            }
            if (j == SYS_T)
            {
                gf.gf_sqr_poly(SYS_T, poly, m[j], m[j >>> 1], temp);
            }
        }

        // Irreducible 2.4.1 - 3. Compute the minimal polynomial g of β over Fq. (By definition g is monic and irre-
        // ducible, and g(β) = 0.)

        // gaussian
        for (int j = 0; j < SYS_T; j++)
        {
            for (int k = j + 1; k < SYS_T; k++)
            {
                short mask = gf.gf_iszero(m[j][j]);
                for (int c = j; c < SYS_T + 1; c++)
                {
                    m[c][j] ^= (short)(m[c][k] & mask);
                }
            }

            // Irreducible 2.4.1 - 4. Return g if g has degree t. Otherwise return ⊥
            if (m[j][j] == 0) // return if not systematic
            {
//                System.out.println("FAILED GENERATING IRR POLY");
                return -1;

            }

            short inv = gf.gf_inv(m[j][j]);

            for (int c = j; c < SYS_T + 1; c++)
            {
                m[c][j] = gf.gf_mul(m[c][j], inv);
            }

            for (int k = 0; k < SYS_T; k++)
            {
                if (k != j)
                {
                    short t = m[j][k];

                    for (int c = j; c <= SYS_T; c++)
                    {
                        m[c][k] ^= gf.gf_mul(m[c][j], t);
                    }
                }
            }
        }
        System.arraycopy(m[SYS_T], 0, field, 0, SYS_T);
        return 0;
    }

    /* check if the padding bits of pk are all zero */
    int check_pk_padding(byte[] pk)
    {
        byte b;
        int i, ret;

        b = 0;
        for (i = 0; i < PK_NROWS; i++)
        {
            b |= pk[i * PK_ROW_BYTES + PK_ROW_BYTES - 1];
        }

        b = (byte)((b & 0xff) >>> (PK_NCOLS % 8));
        b -= 1;
        b = (byte)((b & 0xff) >>> 7);
        ret = b;

        return ret - 1;
    }

    /* check if the padding bits of c are all zero */
    int check_c_padding(byte[] c)
    {
        byte b;
        int ret;

        b = (byte)((c[SYND_BYTES - 1] & 0xff) >>> (PK_NROWS % 8));
        b -= 1;
        b = (byte)((b & 0xff) >>> 7);
        ret = b;

        return ret - 1;
    }

    public int getDefaultSessionKeySize()
    {
        return defaultKeySize;
    }

    private static void sort32(int[] temp, int from, int to)
    {
        int top,p,q,r,i;
        int n = to - from;

        if (n < 2) return;
        top = 1;
        while (top < n - top) top += top;

        for (p = top;p > 0;p >>>= 1)
        {
            for (i = 0;i < n - p;++i)
            {
                if ((i & p) == 0)
                {
                    int ab = temp[from + i + p] ^ temp[from + i];
                    int c = temp[from + i + p] - temp[from + i];
                    c ^= ab & (c ^ temp[from + i + p]);
                    c >>= 31;
                    c &= ab;
                    temp[from + i] ^= c;
                    temp[from + i + p] ^= c;
                }
            }
            i = 0;
            for (q = top;q > p;q >>>= 1)
            {
                for (;i < n - q;++i)
                {
                    if ((i & p) == 0)
                    {
                        int a = temp[from + i + p];
                        for (r = q;r > p;r >>>= 1)
                        {
                            int ab = temp[from + i + r] ^ a;
                            int c = temp[from + i + r] - a;
                            c ^= ab & (c ^ temp[from + i + r]);
                            c >>= 31;
                            c &= ab;
                            a ^= c;
                            temp[from + i + r] ^= c;
                        }
                        temp[from + i + p] = a;
                    }
                }
            }
        }
    }

    private static void sort64(long[] temp, int from, int to)
    {
        int top,p,q,r,i;
        int n = to - from;

        if (n < 2) return;
        top = 1;
        while (top < n - top) top += top;

        for (p = top;p > 0;p >>>= 1)
        {
            for (i = 0;i < n - p;++i)
            {
                if ((i & p) == 0)
                {
                    long c = temp[from + i + p] - temp[from + i];
                    c >>>= 63;
                    c = -c;
                    c &= temp[from + i] ^ temp[from + i + p];
                    temp[from + i] ^= c;
                    temp[from + i + p] ^= c;
                }
            }
            i = 0;
            for (q = top;q > p;q >>>= 1)
            {
                for (;i < n - q;++i)
                {
                    if ((i & p) == 0)
                    {
                        long a = temp[from + i + p];
                        for (r = q;r > p;r >>>= 1)
                        {
                            long c = temp[from + i + r] - a;
                            c >>>= 63;
                            c = -c;
                            c &= a ^ temp[from + i + r];
                            a ^= c;
                            temp[from + i + r] ^= c;
                        }
                        temp[from + i + p] = a;
                    }
                }
            }
        }

    }
}