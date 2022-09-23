package org.bouncycastle.pqc.crypto.falcon;

class FalconRNG
{

    byte[] bd;
    long bdummy_u64;
    int ptr;
    byte[] sd;
    long sdummy_u64;
    int type;

    FalconConversions convertor;

    FalconRNG()
    {
        this.bd = new byte[512];
        this.bdummy_u64 = 0;
        this.ptr = 0;
        this.sd = new byte[256];
        this.sdummy_u64 = 0;
        this.type = 0;
        this.convertor = new FalconConversions();
    }

    void prng_init(SHAKE256 src)
    {
        /*
         * To ensure reproducibility for a given seed, we
         * must enforce little-endian interpretation of
         * the state words.
         */
        byte[] tmp = new byte[56];
        long th, tl;
        int i;

        src.inner_shake256_extract(tmp, 0, 56);
        for (i = 0; i < 14; i++)
        {
            int w;

            w = (tmp[(i << 2) + 0] & 0xff)
                | ((tmp[(i << 2) + 1] & 0xff) << 8)
                | ((tmp[(i << 2) + 2] & 0xff) << 16)
                | ((tmp[(i << 2) + 3] & 0xff) << 24);

            System.arraycopy(convertor.int_to_bytes(w), 0, this.sd, i << 2, 4);
        }

        tl = (convertor.bytes_to_int(this.sd, 48) & 0xffffffffL);

        th = (convertor.bytes_to_int(this.sd, 52) & 0xffffffffL);

        System.arraycopy(convertor.long_to_bytes(tl + (th << 32)), 0, this.sd, 48, 8);
        this.prng_refill();
    }

    /*
     * PRNG based on ChaCha20.
     *
     * State consists in key (32 bytes) then IV (16 bytes) and block counter
     * (8 bytes). Normally, we should not care about local endianness (this
     * is for a PRNG), but for the NIST competition we need reproducible KAT
     * vectors that work across architectures, so we enforce little-endian
     * interpretation where applicable. Moreover, output words are "spread
     * out" over the output buffer with the interleaving pattern that is
     * naturally obtained from the AVX2 implementation that runs eight
     * ChaCha20 instances in parallel.
     *
     * The block counter is XORed into the first 8 bytes of the IV.
     */
    void prng_refill()
    {

        int[] CW = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
        };

        long cc;
        int u;

        /*
         * State uses local endianness. Only the output bytes must be
         * converted to little endian (if used on a big-endian machine).
         */
//        cc = *(uint64_t *)(p->state.d + 48);
        cc = convertor.bytes_to_long(this.sd, 48);
        for (u = 0; u < 8; u++)
        {
            int[] state = new int[16];
            int v;
            int i;

//            memcpy(&state[0], CW, sizeof CW);
            System.arraycopy(CW, 0, state, 0, CW.length);
//            memcpy(&state[4], p->state.d, 48);
            System.arraycopy(convertor.bytes_to_int_array(this.sd, 0, 12), 0, state, 4, 12);
            state[14] ^= (int)cc;
            state[15] ^= (int)(cc >>> 32);
            for (i = 0; i < 10; i++)
            {
                QROUND(0, 4, 8, 12, state);
                QROUND(1, 5, 9, 13, state);
                QROUND(2, 6, 10, 14, state);
                QROUND(3, 7, 11, 15, state);
                QROUND(0, 5, 10, 15, state);
                QROUND(1, 6, 11, 12, state);
                QROUND(2, 7, 8, 13, state);
                QROUND(3, 4, 9, 14, state);
            }

            for (v = 0; v < 4; v++)
            {
                state[v] += CW[v];
            }
            for (v = 4; v < 14; v++)
            {
//                state[v] += ((uint32_t *)p->state.d)[v - 4];
                // we multiply the -4 by 4 to account for 4 bytes per int
                state[v] += convertor.bytes_to_int(sd, (4 * v) - 16);
            }
//            state[14] += ((uint32_t *)p->state.d)[10]
//            ^ (uint32_t)cc;
            state[14] += convertor.bytes_to_int(sd, 40) ^ ((int)cc);
//            state[15] += ((uint32_t *)p->state.d)[11]
//            ^ (uint32_t)(cc >> 32);
            state[15] += convertor.bytes_to_int(sd, 44) ^ ((int)(cc >>> 32));
            cc++;

            /*
             * We mimic the interleaving that is used in the AVX2
             * implementation.
             */
            for (v = 0; v < 16; v++)
            {
//                p->buf.d[(u << 2) + (v << 5) + 0] =
//                        (uint8_t)state[v];
//                p->buf.d[(u << 2) + (v << 5) + 1] =
//                        (uint8_t)(state[v] >> 8);
//                p->buf.d[(u << 2) + (v << 5) + 2] =
//                        (uint8_t)(state[v] >> 16);
//                p->buf.d[(u << 2) + (v << 5) + 3] =
//                        (uint8_t)(state[v] >> 24);
                bd[(u << 2) + (v << 5) + 0] =
                    (byte)state[v];
                bd[(u << 2) + (v << 5) + 1] =
                    (byte)(state[v] >>> 8);
                bd[(u << 2) + (v << 5) + 2] =
                    (byte)(state[v] >>> 16);
                bd[(u << 2) + (v << 5) + 3] =
                    (byte)(state[v] >>> 24);
            }
        }
//    *(uint64_t *)(p->state.d + 48) = cc;
        System.arraycopy(convertor.long_to_bytes(cc), 0, sd, 48, 8);


        this.ptr = 0;
    }

    /* see inner.h */
    void prng_get_bytes(byte[] srcdst, int dst, int len)
    {
        int buf;

        buf = dst;
        while (len > 0)
        {
            int clen;

            clen = (bd.length) - ptr;
            if (clen > len)
            {
                clen = len;
            }
//            memcpy(buf, p->buf.d, clen);
            System.arraycopy(bd, 0, srcdst, buf, clen);
            buf += clen;
            len -= clen;
            ptr += clen;
            if (ptr == bd.length)
            {
                this.prng_refill();
            }
        }
    }

    private void QROUND(int a, int b, int c, int d, int[] state)
    {
        state[a] += state[b];
        state[d] ^= state[a];
        state[d] = (state[d] << 16) | (state[d] >>> 16);
        state[c] += state[d];
        state[b] ^= state[c];
        state[b] = (state[b] << 12) | (state[b] >>> 20);
        state[a] += state[b];
        state[d] ^= state[a];
        state[d] = (state[d] << 8) | (state[d] >>> 24);
        state[c] += state[d];
        state[b] ^= state[c];
        state[b] = (state[b] << 7) | (state[b] >>> 25);
    }

    long prng_get_u64()
    {
        int u;

        /*
         * If there are less than 9 bytes in the buffer, we refill it.
         * This means that we may drop the last few bytes, but this allows
         * for faster extraction code. Also, it means that we never leave
         * an empty buffer.
         */
        u = this.ptr;
        if (u >= (this.bd.length) - 9)
        {
            this.prng_refill();
            u = 0;
        }
        this.ptr = u + 8;

        /*
         * On systems that use little-endian encoding and allow
         * unaligned accesses, we can simply read the data where it is.
         */
        return (this.bd[u + 0] & 0xffL)
            | ((this.bd[u + 1] & 0xffL) << 8)
            | ((this.bd[u + 2] & 0xffL) << 16)
            | ((this.bd[u + 3] & 0xffL) << 24)
            | ((this.bd[u + 4] & 0xffL) << 32)
            | ((this.bd[u + 5] & 0xffL) << 40)
            | ((this.bd[u + 6] & 0xffL) << 48)
            | ((this.bd[u + 7] & 0xffL) << 56);
    }

    byte prng_get_u8()
    {
        byte v;

        v = this.bd[this.ptr++];
        if (this.ptr == this.bd.length)
        {
            this.prng_refill();
        }
        return v;
    }
}
