package org.bouncycastle.pqc.crypto.sike;

import java.util.Properties;

import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

abstract class Internal
{
    protected static final int RADIX = 64;
    protected static final int LOG2RADIX = 6;

    protected int CRYPTO_PUBLICKEYBYTES;
    protected int CRYPTO_CIPHERTEXTBYTES;
    protected int CRYPTO_BYTES;
    protected int CRYPTO_SECRETKEYBYTES;


    protected int NWORDS_FIELD;     // Number of words of a n-bit field element
    protected int PRIME_ZERO_WORDS;  // Number of "0" digits in the least significant part of PRIME + 1
    protected int NBITS_FIELD;
    protected int MAXBITS_FIELD;
    protected int MAXWORDS_FIELD;   // Max. number of words to represent field elements
    protected int NWORDS64_FIELD;   // Number of 64-bit words of a 434-bit field element
    protected int NBITS_ORDER;
    protected int NWORDS_ORDER;     // Number of words of oA and oB, where oA and oB are the subgroup orders of Alice and Bob, resp.
    protected int NWORDS64_ORDER;   // Number of 64-bit words of a x-bit element
    protected int MAXBITS_ORDER;
    protected int ALICE;
    protected int BOB;
    protected int OALICE_BITS;
    protected int OBOB_BITS;
    protected int OBOB_EXPON;
    protected int MASK_ALICE;
    protected int MASK_BOB;
    protected int PARAM_A;
    protected int PARAM_C;

    // Fixed parameters for isogeny tree computation
    protected int MAX_INT_POINTS_ALICE;
    protected int MAX_INT_POINTS_BOB;
    protected int MAX_Alice;
    protected int MAX_Bob;
    protected int MSG_BYTES;
    protected int SECRETKEY_A_BYTES;
    protected int SECRETKEY_B_BYTES;
    protected int FP2_ENCODED_BYTES;

    protected boolean COMPRESS;

    // Compressed Parameters
    protected int MASK2_BOB;
    protected int MASK3_BOB;
    protected int ORDER_A_ENCODED_BYTES;
    protected int ORDER_B_ENCODED_BYTES;
    protected int PARTIALLY_COMPRESSED_CHUNK_CT;
    protected int COMPRESSED_CHUNK_CT;
    protected int UNCOMPRESSEDPK_BYTES;
    // Table sizes used by the Entangled basis generation
    protected int TABLE_R_LEN;
    protected int TABLE_V_LEN;
    protected int TABLE_V3_LEN;
    // Parameters for discrete log computations
    // Binary Pohlig-Hellman reduced to smaller logs of order ell^W
    protected int W_2;
    protected int W_3;
    // ell^w
    protected int ELL2_W;
    protected int ELL3_W;
    // ell^(e mod w)
    protected int ELL2_EMODW;
    protected int ELL3_EMODW;
    // # of digits in the discrete log
    protected int DLEN_2; // ceil(eA/W_2)
    protected int DLEN_3; // ceil(eB/W_3)
    // Use compressed tables: FULL_SIGNED


    // Encoding of field elements
    protected int PLEN_2;
    protected int PLEN_3;

    protected long[] PRIME;
    protected long[] PRIMEx2;
    protected long[] PRIMEx4;
    protected long[] PRIMEp1;
    protected long[] PRIMEx16p;
    protected long[] PRIMEp1x64;
    protected long[] Alice_order;        // Order of Alice's subgroup
    protected long[] Bob_order;     // Order of Bob's subgroup
    protected long[] A_gen;    // Alice's generator values {XPA0 + XPA1*iL, XQA0 + xQA1*iL, XRA0 + XRA1*i} in GF(p^2)L, expressed in Montgomery representation
    protected long[] B_gen;    // Bob's generator values {XPB0L, XQB0L, XRB0 + XRB1*i} in GF(p^2)L, expressed in Montgomery representation
    protected long[] Montgomery_R2;    // Montgomery constant Montgomery_R2 = (2^448)^2 mod p434
    protected long[] Montgomery_one;    // Value one in Montgomery representation

    // Fixed parameters for isogeny tree computation
    protected int[] strat_Alice;
    protected int[] strat_Bob;

    //Compressed Encodings
    //todo: abstract this more?
    protected long[] XQB3;
    protected long[] A_basis_zero;
    protected long[] B_basis_zero;
    protected long[] B_gen_3_tors;
    protected long[] g_R_S_im;
    protected long[] g_phiR_phiS_re;
    protected long[] g_phiR_phiS_im;
    protected long[] Montgomery_R;
    protected long[] Montgomery_RB1;
    protected long[] Montgomery_RB2;
    protected long[] threeinv;
    protected int[] ph2_path;
    protected int[] ph3_path;
    protected long[] u_entang;
    protected long[] u0_entang;
    protected long[][] table_r_qr;
    protected long[][] table_r_qnr;
    protected long[][] table_v_qr;
    protected long[][] table_v_qnr;
    protected long[][][] v_3_torsion;

    protected long[] T_tate3;
    protected long[] T_tate2_firststep_P;
    protected long[] T_tate2_P;
    protected long[] T_tate2_firststep_Q;
    protected long[] T_tate2_Q;

    ///Compressed Dlogs
    protected long[] ph2_T;
    protected long[] ph2_T1;
    protected long[] ph2_T2;
    protected long[] ph3_T;
    protected long[] ph3_T1;
    protected long[] ph3_T2;


    static protected int[] ReadIntsFromProperty(Properties props, String key, int intSize)
    {
        int[] ints = new int[intSize];
        String s = props.getProperty(key);
        String[] vals = s.split(",");
        for (int i = 0; i != vals.length; i++)
        {
            ints[i] = Integer.parseInt(vals[i]);
        }
        return ints;
    }

    static protected long[] ReadFromProperty(Properties props, String key, int longSize)
    {
        String s = props.getProperty(key);
        s = s.replaceAll(",", "");
        byte[] bytes = Hex.decode(s);
        long[] longs = new long[longSize];
        for (int i = 0; i < bytes.length / 8; i++)
        {
            longs[i] = Pack.bigEndianToLong(bytes, i * 8);
        }
        return longs;
    }

    static protected long[][] ReadFromProperty(Properties props, String key, int d1Size, int d2Size)
    {
        String s = props.getProperty(key);
        s = s.replaceAll(",", "");
        byte[] bytes = Hex.decode(s);
        long[][] longs = new long[d1Size][d2Size];
        int i, j;
        for (int x = 0; x < bytes.length / 8; x++)
        {
            i = x / d2Size;
            j = x % d2Size;
            longs[i][j] = Pack.bigEndianToLong(bytes, x * 8);
        }
        return longs;
    }

    static protected long[][][] ReadFromProperty(Properties props, String key, int d1Size, int d2Size, int d3Size)
    {
        String s = props.getProperty(key);
        s = s.replaceAll(",", "");
        byte[] bytes = Hex.decode(s);
        long[][][] longs = new long[d1Size][d2Size][d3Size];
        int i, j, k;
        for (int x = 0; x < bytes.length / 8; x++)
        {
            i = x / (d2Size * d3Size);
            j = x % (d2Size * d3Size) / d3Size;
            k = x % d3Size;
            longs[i][j][k] = Pack.bigEndianToLong(bytes, x * 8);
        }
        return longs;
    }


}
