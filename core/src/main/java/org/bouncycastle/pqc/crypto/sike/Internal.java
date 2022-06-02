package org.bouncycastle.pqc.crypto.sike;

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
    protected boolean COMPRESSED_TABLES; // todo: maybe not needed -> remove
    protected int ELL2_FULL_SIGNED; // Uses signed digits to reduce table size by half
    protected int ELL3_FULL_SIGNED; // Uses signed digits to reduce table size by half


    // Encoding of field elements
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
    protected long[] Montgomery_RB1;
    protected long[] Montgomery_RB2;
    protected long[] threeinv;
    protected long[] ph2_path;
    protected long[] ph3_path;
    protected long[] u_entang;
    protected long[] u0_entang;
    protected long[] table_r_qr;
    protected long[] table_r_qnr;
    protected long[] table_v_qr;
    protected long[] table_v_qnr;
    protected long[] v_3_torsion;
    ///

//        protected void fpcopy(){};
//        protected void fpzero(){};
//        protected void fpadd(){};
//        protected void fpsub(){};
//        protected void fpneg(){};
//        protected void fpdiv2(){}; //todo
//        protected void fpcorrection(){};
//        protected void fpmul_mont(){};
//        protected void fpsqr_mont(){};
//        protected void fpinv_mont(){};
//        protected void fpinv_chain_mont(){};
//        protected void fpinv_mont_bingcd(){};
//        protected void fp2copy(){};
//        protected void fp2zero(){};
//        protected void fp2add(){};
//        protected void fp2sub(){};
//        protected void mp_sub_p2(){};
//        protected void mp_sub_p4(){};
//        protected void sub_p4(){};
//        protected void fp2neg(){};
//        protected void fp2div2(){};
//        protected void fp2correction(){};
//        protected void fp2mul_mont(){};
//        protected void fp2sqr_mont(){};
//        protected void fp2inv_mont(){};
//        protected void fp2inv_mont_bingcd(){};
//        protected void fpequal_non_constant_time(){};
//        protected void mp_add_asm(){};
//        protected void mp_subaddx2_asm(){};
//        protected void mp_dblsubx2_asm(){};
}
