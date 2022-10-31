package org.bouncycastle.pqc.crypto.gemss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;


class GeMSSEngine
{
    private SecureRandom random;
    final int K; //{128, 192, 256}
    final int HFEn;// {174, 175, 177, 178, 265, 266, 268, 270, 271, 354, 358, 364, 366, 402, 537, 544}
    final int HFEv;// {11, 12, 13, 14, 15, 18, 20, 21, 22, 23, 24, 25, 26, 29, 32, 33, 35}
    final int HFEDELTA;// {10, 12, 13, 15, 18, 21, 22, 24, 25, 29, 30, 32, 33, 34, 35}
    final int NB_ITE;//{1, 3, 4}
    final int HFEDeg;// {17, 129, 513, 640, 1152}
    //Pair of HFEDegI and HFEDegJ:{(9, 0), (7,0), (4,0), (9, 7), (10, 7)}
    final int HFEDegI;// {4, 7, 9, 10}
    final int HFEDegJ;// {7, 0}
    //final int HFEs;// {0}
    final int HFEnv;//{186, 187, 189, 190, 192, 193, 277, 285, 288, 289, 291, 292, 295, 387, 390, 393, 396, 399, 420, 563, 576}
    final int HFEm;//{162, 163, 243, 253, 256, 257, 324, 333, 384, 512}
    final int NB_BITS_UINT = 64;
    final int HFEnq;
    final int HFEnr;//{9, 10, 12, 14, 15, 18, 24, 25, 32, 38, 44, 46, 47, 49, 50,}
    int LOG_odd_degree;
    int HFE_odd_degree;
    //int NB_BITS_GFqn_SUP;
    int NB_WORD_GFqn;//{3, 5, 6, 7, 9}
    //int NB_BITS_GFqnv_SUP;
    int NB_WORD_GF2nv;
    //int NB_MONOMIAL;
    int NB_MONOMIAL_VINEGAR;
    int NB_MONOMIAL_PK;
    final int HFEnvq;// = HFEnv / NB_BITS_UINT; //NB_VARq
    final int HFEnvr;//{0, 1, 3, 6, 9, 12, 15, 21, 29, 32, 35, 36, 39, 51, 58, 59, 61, 62}
    int LTRIANGULAR_NV_SIZE;
    final int LTRIANGULAR_N_SIZE;
    final int SIZE_VECTOR_t = 0;
    //final int GFq = 2;
    final int SIZE_SEED_SK;
    int MQnv_GFqn_SIZE;
    final int NB_WORD_MUL;
    int K3;
    int K2;
    int K1;
    boolean __PENTANOMIAL_GF2N__ = false;
    //boolean __TRINOMIAL_GF2N__ = false;
    int NB_WORD_MMUL;//{6, 9, 12, 13, 17}
    //int NB_BITS_MMUL_SUP;
    int MQv_GFqn_SIZE;
    final int KI;
    final int KI64;
    int K3mod64;
    int K364;
    //int K364mod64;
    int K264;
    int K164;
    //    int K1mod64;
    //    int K2mod64;
    final boolean ENABLED_REMOVE_ODD_DEGREE;
    final int MATRIXnv_SIZE;
    /* Number of UINT of matrix m*m in GF(2) */
    final int HFEmq;
    final int HFEmr;
    //int NB_BITS_GFqm_SUP;
    int NB_WORD_GF2m;
    final int HFEvq;
    final int HFEvr;
    final int NB_WORD_GFqv;
    final int HFEmq8;// = (HFEm >>> 3);
    final int HFEmr8; //{0, 2, 3, 4, 5, 7}
    final int NB_BYTES_GFqm;// = (HFEmq8 + ((HFEmr8 != 0) ? 1 : 0));
    final int ACCESS_last_equations8;
    final int NB_BYTES_EQUATION;
    //final int HFENq8;
    final int HFENr8;
    final int NB_WORD_UNCOMP_EQ;
    final int HFENr8c;
    //final int HFEnvqm1;// = (HFEnv - 1) >>> 6;
    //final int HFEnvrm1;// = (HFEnv - 1) & 63;
    final int LOST_BITS;
    final int NB_WORD_GF2nvm;
    final int SIZE_SIGN_UNCOMPRESSED;
    final int SIZE_DIGEST;
    final int SIZE_DIGEST_UINT;
    //int SIZE_2_DIGEST;
    //    int EQUALHASH_NOCST;
    //    int COPYHASH;
    //final int HFEnvq8;
    final int HFEnvr8;
    final int MASK8_GF2nv;
    final int NB_BYTES_GFqnv;
    final int VAL_BITS_M;// = (((HFEDELTA + HFEv) < (8 - HFEmr8)) ? (HFEDELTA + HFEv) : (8 - HFEmr8));
    final boolean EUF_CMA_PROPERTY = false;
    final int SIZE_SALT_BITS;
    final int SIZE_SALT;
    final int SIZE_SALT_WORD;
    final long MASK_GF2m;// = maskUINT(HFEmr);
    //final int NB_WORD_EQ;// = HFEnq + (HFEnr != 0 ? 1 : 0);
    final int LEN_UNROLLED_64 = 4;
    int NB_COEFS_HFEPOLY;
    //    int NB_COEFS_HFEVPOLY;
    int NB_UINT_HFEVPOLY;
    final int MATRIXn_SIZE;
    //final int NB_UINT_HFEPOLY;
    final long MASK_GF2n;
    final int NB_BYTES_GFqn;
    //final int SIZE_PK_HFE;
    final int SIZE_SIGN_HFE;
    private int buffer;
    final int ShakeBitStrength;
    final int Sha3BitStrength;

    public GeMSSEngine(int K, int HFEn, int HFEv, int HFEDELTA, int NB_ITE, int HFEDeg,
                       int HFEDegI, int HFEDegJ)//int HFEs
    {
        this.K = K;
        this.HFEn = HFEn;
        this.HFEv = HFEv;
        this.HFEDELTA = HFEDELTA;
        this.NB_ITE = NB_ITE;
        this.HFEDeg = HFEDeg;
        this.HFEDegI = HFEDegI;
        this.HFEDegJ = HFEDegJ;
        //this.HFEs = HFEs;
        HFEnv = HFEn + HFEv;
        HFEnq = HFEn >>> 6;
        HFEnr = HFEn & 63;
        HFEnvq = HFEnv >>> 6;
        HFEnvr = HFEnv & 63;
        SIZE_SEED_SK = K >>> 3;
        NB_WORD_MUL = ((((HFEn - 1) << 1) >>> 6) + 1);
        KI = HFEn & 63;
        KI64 = 64 - KI;
        HFEm = HFEn - HFEDELTA;
        HFEmq = HFEm >>> 6;
        HFEmr = HFEm & 63;
        HFEvq = HFEv >>> 6;
        HFEvr = HFEv & 63;
        NB_WORD_GFqv = HFEvr != 0 ? HFEvq + 1 : HFEvq;
        HFEmq8 = HFEm >>> 3;
        HFEmr8 = HFEm & 7;
        NB_BYTES_GFqm = (HFEmq8 + ((HFEmr8 != 0) ? 1 : 0));
        NB_WORD_UNCOMP_EQ = ((((HFEnvq * (HFEnvq + 1)) >>> 1) * NB_BITS_UINT) + (HFEnvq + 1) * HFEnvr);
        //HFEnvqm1 = (HFEnv - 1) >>> 6;
        //HFEnvrm1 = (HFEnv - 1) & 63;
        //HFEnvq8 = HFEnv >>> 3;
        HFEnvr8 = (HFEnv & 7);
        MASK8_GF2nv = (1 << HFEnvr8) - 1;
        NB_BYTES_GFqnv = ((HFEnv >>> 3) + ((HFEnvr8 != 0) ? 1 : 0));
        VAL_BITS_M = Math.min(HFEDELTA + HFEv, 8 - HFEmr8);
        MASK_GF2m = maskUINT(HFEmr);
        //NB_WORD_EQ = HFEnq + (HFEnr != 0 ? 1 : 0);
        MASK_GF2n = maskUINT(HFEnr);
        NB_BYTES_GFqn = (HFEn >>> 3) + (((HFEn & 7) != 0) ? 1 : 0);
        if (K <= 128)
        {
            ShakeBitStrength = 128;
            Sha3BitStrength = 256;
        }
        else
        {
            ShakeBitStrength = 256;
            if (K <= 192)
            {
                Sha3BitStrength = 384;
            }
            else
            {
                Sha3BitStrength = 512;
            }
        }
        NB_WORD_GFqn = HFEnq + (HFEnr != 0 ? 1 : 0);
        /* To choose macro for NB_WORD_GFqn*64 bits */
        //NB_BITS_GFqn_SUP = NB_WORD_GFqn << 6;
        LTRIANGULAR_N_SIZE = (((HFEnq * (HFEnq + 1)) >>> 1) * NB_BITS_UINT + NB_WORD_GFqn * HFEnr);
        MATRIXn_SIZE = HFEn * NB_WORD_GFqn;
        NB_WORD_GF2nv = HFEnvq + (HFEnvr != 0 ? 1 : 0);
        //NB_BITS_GFqnv_SUP = NB_WORD_GF2nv << 6;
        MATRIXnv_SIZE = HFEnv * NB_WORD_GF2nv;
        LTRIANGULAR_NV_SIZE = (((HFEnvq * (HFEnvq + 1)) >>> 1) * NB_BITS_UINT + NB_WORD_GF2nv * HFEnvr);
//        if (GFq == 2)
//        {
        //NB_MONOMIAL = (((HFEn * (HFEn + 1)) >>> 1) + 1);
        NB_MONOMIAL_VINEGAR = (((HFEv * (HFEv + 1)) >>> 1) + 1);
        NB_MONOMIAL_PK = (((HFEnv * (HFEnv + 1)) >>> 1) + 1);
//        }
//        else
//        {
//            NB_MONOMIAL = (((HFEn * (HFEn + 3)) >>> 1) + 1);
//            NB_MONOMIAL_VINEGAR = (((HFEv * (HFEv + 3)) >>> 1) + 1);
//            NB_MONOMIAL_PK = (((HFEnv * (HFEnv + 3)) >>> 1) + 1);
//        }
        MQnv_GFqn_SIZE = NB_MONOMIAL_PK * NB_WORD_GFqn;
        MQv_GFqn_SIZE = NB_MONOMIAL_VINEGAR * NB_WORD_GFqn;
        ACCESS_last_equations8 = NB_MONOMIAL_PK * HFEmq8;
        NB_BYTES_EQUATION = (NB_MONOMIAL_PK + 7) >>> 3;
        //HFENq8 = NB_MONOMIAL_PK >>> 3;
        HFENr8 = NB_MONOMIAL_PK & 7;
        HFENr8c = ((8 - HFENr8) & 7);
        //MQ_GFqm8_SIZE = (NB_MONOMIAL_PK * NB_BYTES_GFqm + ((8 - (NB_BYTES_GFqm & 7)) & 7));
        LOST_BITS = (HFEmr8 - 1) * HFENr8c;
        NB_WORD_MMUL = ((((HFEn - 1) << 1) >>> 6) + 1);
        //NB_BITS_MMUL_SUP = NB_WORD_MMUL << 5;
        switch (HFEn)
        {
        case 174:
            //gemss128
            K3 = 13;
            break;
        case 175:
            //bluegemss128, whitegemss128
            K3 = 16;
            break;
        case 177:
            //redgemss128, cyangemss128
            K3 = 8;
            break;
        case 178:
            //magentagemss128
            K3 = 31;
            break;
        case 265:
            //gemss192, bluegemss192
            K3 = 42;
            break;
        case 266:
            //redgemss192,fgemss128,dualmodems128
            K3 = 47;
            break;
        case 268:
            //whitegemss192
            K3 = 25;
            break;
        case 270:
            //cyangemss192
            K3 = 53;
            break;
        case 271:
            //magentagemss192
            K3 = 58;
            break;
        case 354:
            //gemss256
            K3 = 99;
            break;
        case 358:
            //redgemss256, bluegemss256
            K3 = 57;
            break;
        case 364:
            //whitegemss256, cyangemss256
            K3 = 9;
            break;
        case 366:
            //magentagemss256
            K3 = 29;
            break;
        case 402:
            //fgemss192,dualmodems192
            K3 = 171;
            break;
        case 537:
            //fgemss256
            K3 = 10;
            K2 = 2;
            K1 = 1;
            break;
        case 544:
            //dualmodems256
            K3 = 128;
            K2 = 3;
            K1 = 1;
            break;
        default:
            throw new IllegalArgumentException("error: need to add support for HFEn=" + HFEn);
        }
        if (K2 != 0)
        {
            /* Choice of pentanomial for modular reduction in GF(2^n) */
            __PENTANOMIAL_GF2N__ = true;
            K164 = 64 - K1;
            K264 = 64 - K2;
//            K1mod64 = K1 & 63;
//            K2mod64 = K2 & 63;
        }
//        else if (K3 != 0)
//        {
//            /* Choice of trinomial for modular reduction in GF(2^n) */
//            __TRINOMIAL_GF2N__ = true;
//        }
        K3mod64 = K3 & 63;
        K364 = 64 - K3mod64;
        //K364mod64 = K364 & 63;
        if ((HFEDeg & 1) == 0)//HFEs != 0 ||(HFEDeg & 1) == 0
        {
            // Set to 1 to remove terms which have an odd degree strictly greater than HFE_odd_degree
            ENABLED_REMOVE_ODD_DEGREE = true;
            /* HFE_odd_degree = 1 + 2^LOG_odd_degree */
            LOG_odd_degree = HFEDegI;//(HFEDegI - HFEs);
            HFE_odd_degree = ((1 << (LOG_odd_degree)) + 1);
            if ((HFEDeg & 1) != 0)
            {
                throw new IllegalArgumentException("HFEDeg is odd, so to remove the leading term would decrease the degree.");
            }

            if (HFE_odd_degree > HFEDeg)
            {
                throw new IllegalArgumentException("It is useless to remove 0 term.");
            }
            if (HFE_odd_degree <= 1)
            {
                throw new IllegalArgumentException("The case where the term X^3 is removing is not implemented.");
            }
        }
        else
        {
            ENABLED_REMOVE_ODD_DEGREE = false;
        }
        NB_WORD_GF2m = HFEmq + (HFEmr != 0 ? 1 : 0);
        //NB_BITS_GFqm_SUP = NB_WORD_GF2m << 6;
        NB_WORD_GF2nvm = NB_WORD_GF2nv - NB_WORD_GF2m + (HFEmr != 0 ? 1 : 0);
        SIZE_SIGN_UNCOMPRESSED = NB_WORD_GF2nv + (NB_ITE - 1) * NB_WORD_GF2nvm;
        if (K <= 80)
        {
            SIZE_DIGEST = 20;
            SIZE_DIGEST_UINT = 3;
        }
        else if (K <= 128)
        {
            SIZE_DIGEST = 32;
            SIZE_DIGEST_UINT = 4;
            //SIZE_2_DIGEST = 64;
            //EQUALHASH_NOCST = ISEQUAL4_NOCST;
            //COPYHASH = COPY4;
        }
        else if (K <= 192)
        {
            SIZE_DIGEST = 48;
            SIZE_DIGEST_UINT = 6;
            //SIZE_2_DIGEST = 96;
//            EQUALHASH_NOCST = ISEQUAL6_NOCST;
//            COPYHASH = COPY6;
        }
        else
        {
            SIZE_DIGEST = 64;
            SIZE_DIGEST_UINT = 8;
            //SIZE_2_DIGEST = 128;
//            EQUALHASH_NOCST = ISEQUAL8_NOCST;
//            COPYHASH = COPY8;
        }
        if (EUF_CMA_PROPERTY)
        {
            SIZE_SALT_BITS = 128;
            SIZE_SALT = 16;
            SIZE_SALT_WORD = 2;
        }
        else
        {
            SIZE_SALT_BITS = 0;
            SIZE_SALT = 0;
            SIZE_SALT_WORD = 0;
        }
        int NB_COEFS_HFEVPOLY;
        if (HFEDeg == 1)
        {
            NB_COEFS_HFEPOLY = 1;
            NB_COEFS_HFEVPOLY = NB_MONOMIAL_VINEGAR;
        }
        else
        {
//            if (GFq == 2)
//            {
            if (((HFEDeg & 1) == 0))//HFEs != 0 || ((HFEDeg & 1) == 0)
            {
                //ENABLED_REMOVE_ODD_DEGREE 0
                NB_COEFS_HFEPOLY = (2 + HFEDegJ + ((HFEDegI * (HFEDegI - 1)) >>> 1) + LOG_odd_degree);
            }
            else
            {
                //ENABLED_REMOVE_ODD_DEGREE 1
                NB_COEFS_HFEPOLY = (2 + HFEDegJ + ((HFEDegI * (HFEDegI + 1)) >>> 1));
            }
            //}
            NB_COEFS_HFEVPOLY = NB_COEFS_HFEPOLY + (NB_MONOMIAL_VINEGAR - 1) + (HFEDegI + 1) * HFEv;
        }
        NB_UINT_HFEVPOLY = NB_COEFS_HFEVPOLY * NB_WORD_GFqn;
        SIZE_SIGN_HFE = ((HFEnv + (NB_ITE - 1) * (HFEnv - HFEm) + SIZE_SALT_BITS) + 7) >> 3;
    }

    /**
     * @return 0 if the result is correct, ERROR_ALLOC for error from
     * malloc/calloc functions.
     * @brief Computation of the multivariate representation of a HFEv polynomial.
     * @details Here, for each term of F, X is replaced by sum a_i x_i.
     * @param[in] F   A monic HFEv polynomial in GF(2^n)[X,x_(n+1),...,x_(n+v)]
     * stored with a sparse representation.
     * @param[out] MQS The multivariate representation of F, a MQ system with
     * n equations in GF(2)[x1,...,x_(n+v)]. MQS is stored as one equation in
     * GF(2^n)[x1,...,x_(n+v)] (monomial representation + quadratic form cst||Q).
     * @remark Requires to allocate MQnv_GFqn_SIZE words for MQS.
     * @remark Requirement: F is monic.
     * @remark Constant-time implementation.
     */
    int genSecretMQS_gf2(Pointer MQS, Pointer F)
    {
        Pointer alpha_vec = new Pointer((HFEDegI + 1) * (HFEn - 1) * NB_WORD_GFqn);
        //genCanonicalBasis_gf2n(alpha_vec)
        Pointer a_vec = new Pointer(alpha_vec);
        Pointer F_cp;
        Pointer MQS_cp;
        int i, j;
//        if (NB_WORD_GFqn == 1)
//        {
//            for (j = 1; j < HFEn; ++j)
//            {
//                /* a^j */
//                a_vec.set(1L << j);
//            }
//        }
//        else
//        {
        for (j = 1; j < NB_BITS_UINT; ++j)
        {
            /* It is a^(i*NB_BITS_UINT + j) */
            a_vec.set(1L << j);
            a_vec.move(NB_WORD_GFqn);
        }
        a_vec.moveIncremental();
        for (i = 1; i < HFEnq; ++i)
        {
            a_vec.set(1L);
            a_vec.move(NB_WORD_GFqn);
            /* Put the bit 1 at the position j */
            for (j = 1; j < NB_BITS_UINT; ++j)
            {
                /* It is a^(i*NB_BITS_UINT + j) */
                a_vec.set(1L << j);
                a_vec.move(NB_WORD_GFqn);
            }
            a_vec.moveIncremental();
        }
        /* i = NB_WORD_GFqn-1 */
//            if (HFEnr != 0)
//            {
        a_vec.set(1);
        a_vec.move(NB_WORD_GFqn);
        for (j = 1; j < HFEnr; ++j)
        {
            a_vec.set(1L << j);
            a_vec.move(NB_WORD_GFqn);
        }
        //a_vec.moveIncremental();
        //}
        a_vec.move(1 - NB_WORD_GFqn);//-NB_WORD_GFqn
        //}

        //int loop_end = HFEDegI != HFEDegJ ? HFEDegI : HFEDegI + 1;
        Pointer alpha_vec_tmp = new Pointer(alpha_vec);
        for (i = 0; i < HFEDegI; ++i)
        {
            for (j = 1; j < HFEn; ++j)
            {
                /* a^(2^(i+1)) = (a^(2^i))^2 */
                sqr_gf2n(a_vec, alpha_vec_tmp);
                a_vec.move(NB_WORD_GFqn);
                alpha_vec_tmp.move(NB_WORD_GFqn);
            }
        }
        Pointer lin = new Pointer(HFEn * NB_WORD_GFqn);
        MQS.copyFrom(F, NB_WORD_GFqn);
        //System.arraycopy(F.getArray(), 0, MQS.getArray(), 0, NB_WORD_GFqn);
//        if (HFEv != 0)
//        {
        F_cp = new Pointer(F, NB_WORD_GFqn);
        /* +NB_WORD_GFqn because the constant is counted 2 times */
        MQS_cp = new Pointer(MQS, MQnv_GFqn_SIZE - MQv_GFqn_SIZE + NB_WORD_GFqn);
            /* Copy the linear and quadratic terms of the constant in
            GF(2^n)[y1,...,yv] */
        for (i = 1; i < NB_MONOMIAL_VINEGAR; ++i)
        {
            MQS_cp.copyFrom(F_cp, NB_WORD_GFqn);
            MQS_cp.move(NB_WORD_GFqn);
            F_cp.move(NB_WORD_GFqn);
        }
        //}
        a_vec.changeIndex(alpha_vec);
//        if (HFEDeg == 1)
//        {
////            int lin_cp = 0;
////            /* j=0 : mul(*F_cp,1) */
////            set1_gf2n(lin_cp);
////            lin_cp += NB_WORD_GFqn;
////            for (j = 1; j < HFEn; ++j)
////            {
////                copy_gf2n(lin_cp, a_vec);
////                a_vec += NB_WORD_GFqn;
////                lin_cp += NB_WORD_GFqn;
////            }
//        }
//        else
//        {
//        if (HFEv == 0)
//        {
//            F_cp = new Pointer(F, NB_WORD_GFqn);
//        }
        //LINEAR_CASE_INIT_REF(a_vec);
        Pointer lin_cp = new Pointer(lin);
        /* j=0 : mul(*F_cp,1) */
        lin_cp.copyFrom(F_cp, NB_WORD_GFqn);
        lin_cp.move(NB_WORD_GFqn);
        for (j = 1; j < HFEn; ++j)
        {
            mul_gf2n(lin_cp, F_cp, a_vec);
            a_vec.move(NB_WORD_GFqn);
            lin_cp.move(NB_WORD_GFqn);
        }
        F_cp.move(NB_WORD_GFqn);
//        if (HFEv != 0)
//        {
        Pointer a_veci = new Pointer(alpha_vec);
        MQS_cp = new Pointer(MQS, (HFEn + 1) * NB_WORD_GFqn);
        for (j = 0; j < HFEv; ++j)
        {
            MQS_cp.copyFrom(0, F_cp, j * NB_WORD_GFqn, NB_WORD_GFqn);
            MQS_cp.move(NB_WORD_GFqn);
        }
        for (i = 1; i < HFEn; ++i)
        {
            MQS_cp.move((HFEn - i) * NB_WORD_GFqn);
            for (j = 0; j < HFEv; ++j)
            {
                mul_gf2n(MQS_cp, new Pointer(F_cp, j * NB_WORD_GFqn), a_veci);
                MQS_cp.move(NB_WORD_GFqn);
            }
            a_veci.move(NB_WORD_GFqn);
        }
        F_cp.move(HFEv * NB_WORD_GFqn);
//        }
//        else
//        {
//            a_veci = new Pointer(a_vec);
//        }
//        if (HFEDeg == 2)
//        {
//            /* Monic case */
//            //LINEAR_MONIC_CASE_REF(a_veci);
//        }
//        else
//        {
        LINEAR_CASE_REF(lin, F_cp, a_veci, MQS);
        /* Quadratic term X^3 */
        /* The quadratic terms of MQS are not initialised */
        Pointer a_vecj = new Pointer(alpha_vec);
//        if (HFEDeg == 3)
//        {
//            //QUADRATIC_MONIC_CASE_INIT_REF(a_vec,a_vecj);
//        }
//        else
//        {
        //QUADRATIC_CASE_INIT_REF(a_vec, a_vecj);
        /* One term */
        MQS_cp = new Pointer(MQS, NB_WORD_GFqn);
        /* Compute the coefficient of x_0^2 : it is (a^0)^2 = 1 */
        MQS_cp.copyFrom(F_cp, NB_WORD_GFqn);
        //copy_gf2n(MQS, MQS_cp, F, F_cp);
        MQS_cp.move(NB_WORD_GFqn);
        /* Compute the coefficient of x_0*x_(ja+1) : it is 1 for x_0 */
        Pointer tmp1 = new Pointer(NB_WORD_GFqn);
        for (int ja = 0; ja < HFEn - 1; ++ja)
        {
            /* x_0*x_(ja+1) + x_(ja+1)*x_0 */
            tmp1.setRangeFromXor(0, a_vecj, ja * NB_WORD_GFqn, a_vec, ja * NB_WORD_GFqn, NB_WORD_GFqn);
            mul_gf2n(MQS_cp, tmp1, F_cp);
            MQS_cp.move(NB_WORD_GFqn);
        }
        JUMP_VINEGAR_REF(MQS_cp);
        Pointer tmp_i = new Pointer(NB_WORD_GFqn);
        Pointer tmp_j = new Pointer(NB_WORD_GFqn);
        for (int ia = 1; ia < HFEn; ++ia, tmp_i.reset(), tmp_j.reset())
        {
            mul_gf2n(tmp_i, a_vec, F_cp);
            mul_gf2n(tmp_j, a_vecj, F_cp);
            /* Compute the coefficient of x_ia^2 */
            mul_gf2n(MQS_cp, a_vec, tmp_j);
            MQS_cp.move(NB_WORD_GFqn);

            /* Compute the coefficient of x_ia*x_(ja+1) */
            for (int ja = 1; ja < (HFEn - ia); ++ja)
            {
                //tmp1.reset();
                /* Compute the coefficient of x_ia*x_(ja+1) */
                mul_gf2n(tmp1, tmp_i, new Pointer(a_vecj, ja * NB_WORD_GFqn));
                MQS_cp.copyFrom(tmp1, NB_WORD_GFqn);
                /* Compute the coefficient of x_(ja+1)*x_ia */
                mul_gf2n(tmp1, tmp_j, new Pointer(a_vec, ja * NB_WORD_GFqn));
                add2_gf2(MQS_cp, tmp1, NB_WORD_GFqn);
                MQS_cp.move(NB_WORD_GFqn);
            }
            JUMP_VINEGAR_REF(MQS_cp);
            a_vec.move(NB_WORD_GFqn);
            a_vecj.move(NB_WORD_GFqn);
        }
        F_cp.move(NB_WORD_GFqn);
        /* Here a_vec = row 2 */
        /* Here a_veci = row 2 */
        /* Linear term X^4 */
//        if (HFEDeg == 4)
//        {
//            /* Monic case */
//            //LINEAR_MONIC_CASE_REF(a_veci);
//        }
//        else
//        {
        LINEAR_CASE_REF(lin, F_cp, a_veci, MQS);
        /* Other terms, begin at X^5 */
        /* The current term is X^(q^i + q^j) */
        for (i = 2; i < HFEDegI; ++i)
        {
            /* Here a_vec = row i */
            if (ENABLED_REMOVE_ODD_DEGREE)
            {
                j = (((1 << i) + 1) <= HFE_odd_degree) ? 0 : 1;
                a_vecj.changeIndex(j * (HFEn - 1) * NB_WORD_GFqn);
            }
            else
            {
                a_vecj.changeIndex(alpha_vec);
                j = 0;
            }
            for (; j < i; ++j)
            {
                a_veci.changeIndex(a_vec);
                QUADRATIC_CASE_REF(MQS, F_cp, a_veci, a_vecj);
            }
            a_vec.changeIndex(a_veci);
            /* Here a_vec = row i+1 */
            /* j=i */
            LINEAR_CASE_REF(lin, F_cp, a_veci, MQS);
        }
        /* Remainder */
        /* i = HFEDegi */
        /* The current term is X^(q^HFEDegi + q^j) */
        /* Here a_vec = row i */
        if (ENABLED_REMOVE_ODD_DEGREE)
        {
            j = (((1 << i) + 1) <= HFE_odd_degree) ? 0 : 1;
            a_vecj.changeIndex(j * (HFEn - 1) * NB_WORD_GFqn);
        }
        else
        {
            /* Here a_vec = row i */
            a_vecj.changeIndex(alpha_vec);
            j = 0;
        }
        for (; j < HFEDegJ; ++j)//fgemss192 and fgemss256
        {
            a_veci.changeIndex(a_vec);
            QUADRATIC_CASE_REF(MQS, F, a_veci, a_vecj);
        }
        /* Here a_veci = row i+1 */
        /* j=HFEDegJ */
//        if (HFEDegI == HFEDegJ)
//        {
//            /* j=i */
//            /* It is the leading term and F is monic, so the coefficient is 1 */
//            LINEAR_MONIC_CASE_REF(lin, a_veci);
//        }
//        else
//        {
        a_veci.changeIndex(a_vec);
        //QUADRATIC_MONIC_CASE_REF(a_veci, a_vecj);
        /* One term */
        MQS_cp.changeIndex(NB_WORD_GFqn);
        /* Here a_veci = row i */
        /* Here, a_vecj = row j */
        /* ia = 0 */
        /* Compute the coefficient of x_0^2 : it is (a^0)^2 = 1 */
        MQS_cp.setXor(1);
        MQS_cp.move(NB_WORD_GFqn);
        /* Compute the coefficient of x_0*x_(ja+1) : it is 1 for x_0 */
        for (int ja = 0; ja < HFEn - 1; ++ja)
        {
            tmp1.indexReset();
            /* x_0*x_(ja+1) + x_(ja+1)*x_0 */
            tmp1.setRangeFromXor(0, a_vecj, ja * NB_WORD_GFqn, a_veci, ja * NB_WORD_GFqn, NB_WORD_GFqn);
            //add_gf2(tmp1, new Pointer(a_vecj, ja * NB_WORD_GFqn), new Pointer(a_veci, ja * NB_WORD_GFqn));
            add2_gf2(MQS_cp, tmp1, NB_WORD_GFqn);
            MQS_cp.move(NB_WORD_GFqn);
        }
        JUMP_VINEGAR_REF(MQS_cp);
        for (int ia = 1; ia < HFEn; ++ia)
        {
            tmp1.reset();
            /* Compute the coefficient of x_ia^2 */
            mul_gf2n(tmp1, a_veci, a_vecj);
            add2_gf2(MQS_cp, tmp1, NB_WORD_GFqn);
            MQS_cp.move(NB_WORD_GFqn);
            /* Compute the coefficient of x_ia*x_(ja+1) */
            for (int ja = 1; ja < (HFEn - ia); ++ja)
            {
                /* Compute the coefficient of x_ia*x_(ja+1) */
                mul_gf2n(tmp1, a_veci, new Pointer(a_vecj, ja * NB_WORD_GFqn));
                add2_gf2(MQS_cp, tmp1, NB_WORD_GFqn);
                /* Compute the coefficient of x_(ja+1)*x_ia */
                mul_gf2n(tmp1, a_vecj, new Pointer(a_veci, ja * NB_WORD_GFqn));
                add2_gf2(MQS_cp, tmp1, NB_WORD_GFqn);
                MQS_cp.move(NB_WORD_GFqn);
            }
            JUMP_VINEGAR_REF(MQS_cp);
            a_veci.move(NB_WORD_GFqn);
            a_vecj.move(NB_WORD_GFqn);
        }
        /* Here, a_veci = row i+1 */
        /* Here, a_vecj = row j+1 */
        //}
        //}
        //}
        //}
        //}
        /* Put linear part on "diagonal" of MQS */
        lin_cp = new Pointer(lin);
        MQS_cp = new Pointer(MQS, NB_WORD_GFqn);
        for (i = HFEnv; i > HFEv; --i)
        {
            add2_gf2(MQS_cp, lin_cp, NB_WORD_GFqn);
            lin_cp.move(NB_WORD_GFqn);
            MQS_cp.move(i * NB_WORD_GFqn);
        }
        return 0;
    }

    /* Function mul in GF(2^x), then modular reduction */
    void mul_gf2n(Pointer P, Pointer A, Pointer B)
    {
        long b;
        int i, j;
        int A_orig = A.getIndex(), B_orig = B.getIndex();
        Pointer C = new Pointer(NB_WORD_MUL);
        //mul_gf2x
        /**
         * @brief Multiplication in GF(2)[x].
         * @param[in] A   An element of GF(2^n).
         * @param[in] B   An element of GF(2^n).
         * @param[out] C   C=A*B in GF(2)[x] (the result is not reduced).
         * @remark Constant-time implementation.
         */
        for (i = 0; i < HFEnq; ++i)
        {
            b = B.get();
            /* j=0 */
            C.setXorRangeAndMask(0, A, 0, NB_WORD_GFqn, -(b & 1L));
//            if (HFEnr != 0)
//            {
            /* The last 64-bit block BL of A contains HFEnr bits.
               So, there is not overflow for BL<<j while j<=(64-HFEnr). */
            for (j = 1; j <= (64 - HFEnr); ++j)
            {
                C.setXorRangeAndMaskRotate(0, A, 0, NB_WORD_GFqn, -((b >>> j) & 1L), j);
            }
//            }
//            else
//            {
//                j = 1;
//            }
            for (; j < 64; ++j)
            {
                C.setXorRangeAndMaskRotateOverflow(0, A, 0, NB_WORD_GFqn, -((b >>> j) & 1L), j);
            }
            B.moveIncremental();
            C.moveIncremental();
        }
//        if (HFEnr != 0)
//        {
        b = B.get();
        /* j=0 */
        C.setXorRangeAndMask(0, A, 0, NB_WORD_GFqn, -(b & 1L));
        /* The last 64-bit block BL of A contains HFEnr bits. So, there is not overflow for BL<<j while j<=(64-HFEnr). */
        int loop_end = HFEnr > 32 ? 65 - HFEnr : HFEnr;
        for (j = 1; j < loop_end; ++j)
        {
            C.setXorRangeAndMaskRotate(0, A, 0, NB_WORD_GFqn, -((b >>> j) & 1L), j);
        }
        if (HFEnr > 32)
        {
            for (; j < HFEnr; ++j)
            {
                C.setXorRangeAndMaskRotateOverflow(0, A, 0, NB_WORD_GFqn, -((b >>> j) & 1L), j);
            }
        }
//        }
        C.indexReset();
        //rem_gf2n
        /**
         * @brief Reduction in GF(2^n) of a (2n-1)-coefficients polynomial in
         * GF(2)[x].
         * @param[in] C A (2n-1)-coefficients polynomial in GF(2)[x].
         * @param[out] P   P is Pol reduced in GF(2^n).
         * @remark Requirement: the n-degree irreducible polynomial defining GF(2^n)
         * must be a trinomial or a pentanomial.
         * @remark Requirement: K3<33, or (n,K3) in {(265,42),(266,47),(270,53),
         * (271,58),(354,99),(358,57)}.
         * @remark Requirement: K1<K2<33.
         * @remark Constant-time implementation.
         */
        long R;
//        if (KI != 0)
//        {
        Pointer Q = new Pointer(NB_WORD_GFqn);
        /* Q: Quotient of Pol/x^n, by word of 64-bit */
        for (i = NB_WORD_GFqn; i < NB_WORD_MMUL; ++i)
        {
            Q.set(i - NB_WORD_GFqn, ((C.get(i - 1) >>> KI)) ^ (C.get(i) << KI64));
        }
        if ((NB_WORD_MMUL & 1) != 0)
        {
            Q.set(i - NB_WORD_GFqn, (C.get(i - 1) >>> KI));
        }
        if ((HFEn == 354) && (K3 == 99)) //Gemss256
        {
            Q.setXor((Q.get(3) >>> (K364 + KI)) ^ (Q.get(4) << (K3mod64 - KI)));
            Q.setXor(1, (Q.get(4) >>> (K364 + KI)) ^ (Q.get(5) << (K3mod64 - KI)));
        }
        else if ((HFEn == 358) && (K3 == 57)) //redgemss256, bluegemss256
        {
            /* R: Quotient of C/x^(2n-K3), by word of 64-bit */
            R = (Q.get(4) >>> (K364 + KI)) ^ (Q.get(5) << (K3 - KI));
            Q.setXor(R);
        }
        for (i = 0; i < NB_WORD_GFqn; ++i)
        {
            P.set(i, C.get(i) ^ Q.get(i));
        }
        if (__PENTANOMIAL_GF2N__)//fgemss256 and dualmodems256
        {
            P.setXor((Q.get() << K1) ^ (Q.get() << K2));
            for (i = 1; i < NB_WORD_GFqn; ++i)
            {
                P.setXor(i, (Q.get(i - 1) >>> K164) ^ (Q.get(i) << K1) ^ (Q.get(i - 1) >>> K264) ^ (Q.get(i) << K2));
            }
//            P.setXor(Q.get() << K2);
//            for (i = 1; i < NB_WORD_GFqn; ++i)
//            {
//                P.setXor(i, (Q.get(i - 1) >>> K264) ^ (Q.get(i) << K2));
//            }
        }
        if ((HFEn == 354) && (K3 == 99))//Gemss256
        {
            P.setXor(1, Q.get() << K3mod64);
            P.setXor(2, (Q.get() >>> K364) ^ (Q.get(1) << K3mod64));
            P.setXor(3, (Q.get(1) >>> K364) ^ (Q.get(2) << K3mod64));
            P.setXor(4, (Q.get(2) >>> K364) ^ (Q.get(3) << K3mod64));
            P.setXor(5, Q.get(3) >>> K364);
        }
        else
        {
            P.setXor(Q.get() << K3mod64);
            for (i = 1; i < NB_WORD_GFqn; ++i)
            {
                P.setXor(i, (Q.get(i - 1) >>> K364) ^ (Q.get(i) << K3mod64));
            }
        }
        //if ((K3 != 1) && (!((HFEn == 354) && (K3 == 99))) && (!((HFEn == 358) && (K3 == 57))))
        if ((!((HFEn == 354) && (K3 == 99))) && (!((HFEn == 358) && (K3 == 57))))//Not gemss256 redgemss256 bluegemss256
        {
            /* R: Quotient of Pol/x^(2n-K3), by word of 64-bit */
            if (KI >= K3)
            {
                R = Q.get(NB_WORD_GFqn - 1) >>> (KI - K3mod64);
            }
            else
            {
                R = (Q.get(NB_WORD_GFqn - 2) >>> (K364 + KI)) ^ (Q.get(NB_WORD_GFqn - 1) << (K3mod64 - KI));
            }
            if (__PENTANOMIAL_GF2N__)
            {
//                if (KI >= K2)
//                {
                R ^= Q.get(NB_WORD_GFqn - 1) >>> (KI - K2);
//                }
//                else
//                {
//                    R ^= (Q.get(NB_WORD_GFqn - 2) >>> (K264 + KI)) ^ (Q.get(NB_WORD_GFqn - 1) << (K2 - KI));
//                }
//                if (K1 != 1)
//                {
//                    if (KI >= K1)
//                    {
//                    R ^= Q.get(NB_WORD_GFqn - 1) >>> (KI - K1);
//                    }
//                    else
//                    {
//                        R ^= (Q.get(NB_WORD_GFqn - 2) >>> (K164 + KI)) ^ (Q.get(NB_WORD_GFqn - 1) << (K1 - KI));
//                    }
//                }
            }
            P.setXor(R ^ (R << K3mod64));
            if (__PENTANOMIAL_GF2N__)
            {
                P.setXor((R << K1) ^ (R << K2));
            }
            if (K3 > 32)
            {
                P.setXor(1, R >>> K364);
            }
        }
        P.setAnd(NB_WORD_GFqn - 1, MASK_GF2n);
//        }
//        else
//        {
//            for (i = 0; i < NB_WORD_GFqn; ++i)
//            {
//                P.set(i, C.get(i) ^ C.get(i + NB_WORD_GFqn));
//            }
//
//            if (__PENTANOMIAL_GF2N__)
//            {
//                P.setXor(C.get(NB_WORD_GFqn) << K1);
//                for (i = NB_WORD_GFqn + 1; i < (NB_WORD_GFqn << 1); ++i)
//                {
//                    P.setXor(i - NB_WORD_GFqn, (C.get(i - 1) >>> K164) ^ (C.get(i) << K1));
//                }
//                P.setXor(C.get(NB_WORD_GFqn) << K2);
//                for (i = NB_WORD_GFqn + 1; i < (NB_WORD_GFqn << 1); ++i)
//                {
//                    P.setXor(i - NB_WORD_GFqn, (C.get(i - 1) >>> K264) ^ (C.get(i) << K2));
//                }
//            }
//
//            P.setXor(C.get(NB_WORD_GFqn) << K3);
//            for (i = NB_WORD_GFqn + 1; i < (NB_WORD_GFqn << 1); ++i)
//            {
//                P.setXor(i - NB_WORD_GFqn, (C.get(i - 1) >>> K364) ^ (C.get(i) << K3));
//            }
//
//            R = C.get((NB_WORD_GFqn << 1) - 1) >>> K364;
//            if (__PENTANOMIAL_GF2N__)
//            {
//                R ^= C.get((NB_WORD_GFqn << 1) - 1) >>> K264;
//                if (K1 != 1)
//                {
//                    R ^= C.get((NB_WORD_GFqn << 1) - 1) >>> K164;
//                }
//
//            }
//            P.setXor(R);
//            if (__PENTANOMIAL_GF2N__)
//            {
//                P.setXor(R << K1);
//                P.setXor(R << K2);
//            }
//            P.setXor(R << K3);
//        }
        A.changeIndex(A_orig);
        B.changeIndex(B_orig);
    }

    private void LINEAR_CASE_REF(Pointer lin, Pointer F_cp, Pointer a_vec, Pointer MQS)
    {
        Pointer lin_cp = new Pointer(lin);
        /* j=0 : mul(*F_cp,1)=*F_cp */
        add2_gf2(lin_cp, F_cp, NB_WORD_GFqn);
        lin_cp.move(NB_WORD_GFqn);
        //Pointer a_vec = new Pointer(a_vec);
        for (int j = 1; j < HFEn; ++j)
        {
            Pointer tmp1 = new Pointer(NB_WORD_GFqn);
            mul_gf2n(tmp1, F_cp, a_vec);
            add2_gf2(lin_cp, tmp1, NB_WORD_GFqn);
            a_vec.move(NB_WORD_GFqn);
            lin_cp.move(NB_WORD_GFqn);
        }
        F_cp.move(NB_WORD_GFqn);
        //LINEAR_VCASE_REF(a_vec);
//        if (HFEv != 0)
//        {
        a_vec.move(-((HFEn - 1) * NB_WORD_GFqn));
        Pointer MQS_cp = new Pointer(MQS, (HFEn + 1) * NB_WORD_GFqn);
        for (int j = 0; j < HFEv; ++j)
        {
            add2_gf2(MQS_cp, new Pointer(F_cp, j * NB_WORD_GFqn), NB_WORD_GFqn);
            MQS_cp.move(NB_WORD_GFqn);
        }

        for (int ja = 1; ja < HFEn; ++ja)
        {
            MQS_cp.move((HFEn - ja) * NB_WORD_GFqn);
            for (int j = 0; j < HFEv; ++j)
            {
                Pointer tmp1 = new Pointer(NB_WORD_GFqn);
                mul_gf2n(tmp1, new Pointer(F_cp, j * NB_WORD_GFqn), a_vec);
                add2_gf2(MQS_cp, tmp1, NB_WORD_GFqn);
                MQS_cp.move(NB_WORD_GFqn);
            }
            a_vec.move(NB_WORD_GFqn);
        }
        F_cp.move(HFEv * NB_WORD_GFqn);
        //}
    }

    private void JUMP_VINEGAR_REF(Pointer MQS_cp)
    {
//        if (HFEv != 0)
//        {
        MQS_cp.move(HFEv * NB_WORD_GFqn);
        //}
    }

    /* Compute (*F_cp)*a_vec[ia]*a_vec[ja] */
    /* a_vec[ia]*a_vec[ja] is the term x_ia * x_(ja+1) */
    private void QUADRATIC_CASE_REF(Pointer MQS, Pointer F_cp, Pointer a_veci, Pointer a_vecj)
    {
        Pointer MQS_cp = new Pointer(MQS, NB_WORD_GFqn);
        /* Here a_veci = row i */
        /* Here, a_vecj = row j */
        /* ia = 0 */
        /* Compute the coefficient of x_0^2 : it is (a^0)^2 = 1 */
        add2_gf2(MQS_cp, F_cp, NB_WORD_GFqn);
        MQS_cp.move(NB_WORD_GFqn);
        Pointer tmp1 = new Pointer(NB_WORD_GFqn);
        Pointer tmp_i = new Pointer(NB_WORD_GFqn);
        Pointer tmp_j = new Pointer(NB_WORD_GFqn);
        /* Compute the coefficient of x_0*x_(ja+1) : it is 1 for x_0 */
        for (int ja = 0; ja < HFEn - 1; ++ja)
        {
            /* x_0*x_(ja+1) + x_(ja+1)*x_0 */
            //tmp1.indexReset();
            tmp_i.reset();
            tmp1.setRangeFromXor(0, a_vecj, ja * NB_WORD_GFqn, a_veci, ja * NB_WORD_GFqn, NB_WORD_GFqn);
            //add_gf2(tmp1, new Pointer(a_vecj, ja * NB_WORD_GFqn), new Pointer(a_veci, ja * NB_WORD_GFqn));
            mul_gf2n(tmp_i, tmp1, F_cp);
            add2_gf2(MQS_cp, tmp_i, NB_WORD_GFqn);
            MQS_cp.move(NB_WORD_GFqn);
        }
        JUMP_VINEGAR_REF(MQS_cp);
        for (int ia = 1; ia < HFEn; ++ia)
        {
            mul_gf2n(tmp_i, a_veci, F_cp);
            mul_gf2n(tmp_j, a_vecj, F_cp);
            /* Compute the coefficient of x_ia^2 */
            mul_gf2n(tmp1, a_veci, tmp_j);
            add2_gf2(MQS_cp, tmp1, NB_WORD_GFqn);
            MQS_cp.move(NB_WORD_GFqn);
            /* Compute the coefficient of x_ia*x_(ja+1) */
            for (int ja = 1; ja < (HFEn - ia); ++ja)
            {
                /* Compute the coefficient of x_ia*x_(ja+1) */
                mul_gf2n(tmp1, tmp_i, new Pointer(a_vecj, ja * NB_WORD_GFqn));
                add2_gf2(MQS_cp, tmp1, NB_WORD_GFqn);
                /* Compute the coefficient of x_(ja+1)*x_ia */
                mul_gf2n(tmp1, tmp_j, new Pointer(a_veci, ja * NB_WORD_GFqn));
                add2_gf2(MQS_cp, tmp1, NB_WORD_GFqn);
                MQS_cp.move(NB_WORD_GFqn);
            }
            JUMP_VINEGAR_REF(MQS_cp);
            a_veci.move(NB_WORD_GFqn);
            a_vecj.move(NB_WORD_GFqn);
        }
        /* Here, a_veci = row i+1 */
        F_cp.move(NB_WORD_GFqn);
    }

//    private void LINEAR_MONIC_CASE_REF(Pointer lin, Pointer a_vec)
//    {
//        Pointer lin_cp = new Pointer(lin);
//        /* j=0 : mul(*F_cp,1)=*F_cp */
//        lin_cp.setXor(1);
//        lin_cp.move(NB_WORD_GFqn);
//        for (int j = 1; j < HFEn; ++j)
//        {
//            add2_gf2(lin_cp, a_vec, NB_WORD_GFqn);
//            a_vec.move(NB_WORD_GFqn);
//            lin_cp.move(NB_WORD_GFqn);
//        }
//    }

    /**
     * @brief Addition in GF(2^n).
     * @param[in] a   An element of GF(2^n).
     * @param[out] c   c=a+c in GF(2^n).
     * @remark Constant-time implementation.
     */
    void add2_gf2(Pointer c, Pointer a, int len)
    {

        for (int i = 0; i < len; ++i)
        {
            c.setXor(i, a.get(i));
        }
    }

    /**
     * @brief Addition in GF(2^n).
     * @param[in] a   An element of GF(2^n).
     * @param[in] b   An element of GF(2^n).
     * @param[out] c   c=a+b in GF(2^n).
     * @remark Constant-time implementation.
     */
    private void add_gf2(Pointer c, Pointer a, Pointer b)
    {
        for (int i = 0; i < NB_WORD_GFqn; ++i)
        {
            c.set(i, a.get(i) ^ b.get(i));
        }
    }

    private long square_gf2(long Ci)
    {
        Ci = (Ci ^ (Ci << 8)) & (0x00FF00FF00FF00FFL);
        Ci = (Ci ^ (Ci << 4)) & (0x0F0F0F0F0F0F0F0FL);
        Ci = (Ci ^ (Ci << 2)) & (0x3333333333333333L);
        Ci = (Ci ^ (Ci << 1)) & (0x5555555555555555L);
        return Ci;
    }

    /**
     * @brief Squaring in GF(2)[x].
     * @details For each 32-bit block on the input, we use the following strategy:
     * Assume we want to insert a null bit between each bit of 0x00000000FFFFFFFF.
     * We do as following:
     * 0x00000000FFFFFFFF (it is already an insertion of a zero 32-bit packed)
     * 0x0000FFFF0000FFFF (insertion by pack of 16 bits)
     * 0x00FF00FF00FF00FF (insertion by pack of 8 bits)
     * 0x0F0F0F0F0F0F0F0F (insertion by pack of 4 bits)
     * 0x3333333333333333 (insertion by pack of 2 bits)
     * 0x5555555555555555 (insertion by pack of 1 bit).
     * @param[in] A   An element of GF(2^n).
     * @param[out] C   C=A*A in GF(2)[x] (the result is not reduced).
     * @remark Constant-time implementation.
     */
    private void sqr_nocst_gf2x(Pointer C, Pointer A)
    {
        long Ci;
        int i;
        C.move(NB_WORD_MUL - 1);
        if ((NB_WORD_MUL & 1) != 0)
        {
            i = NB_WORD_GFqn - 1;
            /* Lower 32 bits of A[i] */
            Ci = A.get(i);
            Ci = (Ci ^ (Ci << 16)) & 0x0000FFFF0000FFFFL;
            Ci = square_gf2(Ci);
            C.set(Ci);
            C.moveDecremental();
            i = NB_WORD_GFqn - 2;
        }
        else
        {
            i = NB_WORD_GFqn - 1;
        }
        for (; i != -1; --i)
        {
            /* Higher 32 bits of A[i] */
            Ci = A.get(i) >>> 32;
            Ci = (Ci ^ (Ci << 16)) & (0x0000FFFF0000FFFFL);
            Ci = square_gf2(Ci);
            C.set(Ci);
            C.moveDecremental();
            /* Lower 32 bits of A[i] */
            Ci = A.get(i);
            Ci = ((Ci & 0xFFFFFFFFL) ^ (Ci << 16)) & (0x0000FFFF0000FFFFL);
            Ci = square_gf2(Ci);
            C.set(Ci);
            C.moveDecremental();
        }
    }

    /**
     * @brief Reduction in GF(2^n) of a (2n-1)-coefficients square in GF(2)[x].
     * @details The odd degree terms are assumed to be null, and so are not
     * considered.
     * @param[in] Pol A (2n-1)-coefficients square in GF(2)[x].
     * @param[out] P   P is Pol reduced in GF(2^n).
     * @remark Requirement: the odd degree terms of Pol are null.
     * @remark Requirement: the n-degree irreducible polynomial defining GF(2^n)
     * must be a trinomial or a pentanomial.
     * @remark Constant-time implementation.
     */
    private void remsqr_gf2n_ref(Pointer C, Pointer A)
    {
        //sqr_nocst_gf2x
        //sqr_no_simd_gf2x_ref2
        int i;
        long[] res = new long[NB_WORD_MUL];//int?
        for (i = 0; i < NB_WORD_MUL; ++i)
        {
            res[i] = A.get(i);//Pol[i];
        }
        int loop_end;
        /* Only the even degree terms are not zero */
//        if (K3 == 1)
//        {
//            loop_end = HFEn;
//        }
//        else if (((HFEn - 2 + K3) & 1) != 0)
        if (((HFEn - 2 + K3) & 1) != 0)
        {
            loop_end = HFEn - 1 + K3;
        }
        else
        {
            loop_end = HFEn - 2 + K3;
        }
        long bit_i;
        int ind;
        for (i = (HFEn - 1) << 1; i >= loop_end; i -= 2)
        {
            /* Extraction of bit_i x^i */
            bit_i = (res[i >>> 6] >>> (i & 63)) & 1L;
            /* x^n = 1 + ... */
            ind = i - HFEn;
            res[ind >>> 6] ^= bit_i << (ind & 63);
            if (__PENTANOMIAL_GF2N__)
            {
                /* ... + x^;K1 + ... */
                ind = i - HFEn + K1;
                res[ind >>> 6] ^= bit_i << (ind & 63);
                /* ... + x^;K2 + ... */
                ind = i - HFEn + K2;
                res[ind >>> 6] ^= bit_i << (ind & 63);
            }
            /* ... + x^K3 */
            ind = i - HFEn + K3;
            res[ind >>> 6] ^= bit_i << (ind & 63);
        }
//        if (K3 > 1)
//        {
        for (++i; i >= HFEn; --i)
        {
            /* Extraction of bit_i x^i */
            bit_i = (res[i >>> 6] >>> (i & 63)) & 1L;
            /* x^n = 1 + ... */
            ind = i - HFEn;
            res[ind >>> 6] ^= bit_i << (ind & 63);
            if (__PENTANOMIAL_GF2N__)
            {
                /* ... + x^;K1 + ... */
                ind = i - HFEn + K1;
                res[ind >>> 6] ^= bit_i << (ind & 63);
                /* ... + x^;K2 + ... */
                ind = i - HFEn + K2;
                res[ind >>> 6] ^= bit_i << (ind & 63);
            }
            /* ... + x^K3 */
            ind = i - HFEn + K3;
            res[ind >>> 6] ^= bit_i << (ind & 63);
        }
        //}
        for (i = 0; i < NB_WORD_GFqn; ++i)
        {
            C.set(i, res[i]);
        }
//        if (HFEnr != 0)
//        {
        C.setAnd(NB_WORD_GFqn - 1, MASK_GF2n);
        //}
    }

    /* Function sqr in GF(2^x), then modular reduction */
    private void sqr_gf2n(Pointer C, Pointer A)
    {
        Pointer B = new Pointer(NB_WORD_MUL);
        sqr_nocst_gf2x(B, A);
        B.indexReset();
        remsqr_gf2n_ref(C, B);
    }

    private long maskUINT(int k)
    {
        return k != 0 ? (1L << k) - 1L : -1L;
    }

    /* cleanLowerMatrixn: HFEnq, HFEnr
     * cleanLowerMatrixnv: HFEnvq, HFEnvr
     * */
    void cleanLowerMatrix(Pointer L, FunctionParams cleanLowerMatrix)
    {
        int nq, nr;
        long mask;
        int iq, ir;
        //int LTRIANGULAR_SIZE;
        switch (cleanLowerMatrix)
        {
        case N:
            nq = HFEnq;
            nr = HFEnr;
            //LTRIANGULAR_SIZE = LTRIANGULAR_N_SIZE;
            break;
        case NV:
            nq = HFEnvq;
            nr = HFEnvr;
            //LTRIANGULAR_SIZE = LTRIANGULAR_NV_SIZE;
            break;
        default:
            throw new IllegalArgumentException("");
        }
        Pointer L_cp = new Pointer(L);
        //randombytes function is used by GENLOWMATRIX_GF2 function which needs the following line:
//        L_cp.fillRandom(random, LTRIANGULAR_SIZE << 3);
        //randombytes((unsigned char*)L,LTRIANGULAR_SIZE<<3);\
        /* for each row */
        for (iq = 1; iq <= nq; ++iq)
        {
            mask = 0;
            for (ir = 0; ir < NB_BITS_UINT; ++ir)
            {
                /* Put the bit of diagonal to 1 + zeros after the diagonal */
                L_cp.setAnd(mask);
                L_cp.setXor(1L << ir);
                mask <<= 1;
                ++mask;
                L_cp.move(iq);
            }
            /* Next column */
            L_cp.moveIncremental();
        }

        /* iq = HFEnq */
        mask = 0;
        for (ir = 0; ir < nr; ++ir)
        {
            /* Put the bit of diagonal to 1 + zeros after the diagonal */
            L_cp.setAnd(mask);
            L_cp.setXor(1L << ir);
            mask <<= 1;
            ++mask;
            L_cp.move(iq);
        }
    }

    /**
     * @brief Compute the inverse of S=LU a matrix (n,n) or (n+v, n+v) in GF(2), in-place.
     * @details Gauss-Jordan: transform S to Identity and Identity to S^(-1).
     * Here, we do not need to transform S to Identity.
     * We use L to transform Identity to a lower triangular S',
     * then we use U to transform S' to S^(-1).
     * @param[in,out] S   S_inv=L*U, an invertible matrix (n,n) in GF(2),
     * its inverse will be computed in-place.
     * @param[in] L_orig   A lower triangular matrix (n,n) in GF(2).
     * @param[in] U_orig   An upper triangular matrix (n,n) in GF(2), but we
     * require to store its transpose (i.e. contiguous following the columns).
     * @param[in] imluParams chooses size of matrix (n,n) or (n+v, n+v)
     * @remark Requirement: S is invertible.
     * @remark Constant-time implementation.
     */
    void invMatrixLU_gf2(Pointer S, Pointer L_orig, Pointer U_orig, FunctionParams imluParams)
    {
        Pointer Sinv_cpi, Sinv_cpj;
        Pointer L_cpj = new Pointer(L_orig);
        Pointer L = new Pointer(L_orig);
        Pointer U = new Pointer(U_orig);
        long mask;
        int i, iq, ir, j, k;
        int outloopbound, innerloopbound, nextrow, ifCondition, endOfU;
        switch (imluParams)
        {
        case NV:
            S.setRangeClear(0, MATRIXnv_SIZE);
            outloopbound = HFEnvq;
            innerloopbound = HFEnv - 1;
            nextrow = NB_WORD_GF2nv;
            ifCondition = HFEnvr;
            endOfU = LTRIANGULAR_NV_SIZE;
            break;
        case N:
            S.setRangeClear(0, MATRIXn_SIZE);
            outloopbound = HFEnq;
            innerloopbound = HFEn - 1;
            nextrow = NB_WORD_GFqn;
            ifCondition = HFEnr;
            endOfU = LTRIANGULAR_N_SIZE;
            break;
        default:
            throw new IllegalArgumentException("Invalid Input");
        }
        /* Initialize to 0 */
        //S.setRangeClear(0, MATRIXnv_SIZE);
        Sinv_cpi = new Pointer(S);
        Sinv_cpj = new Pointer(S);
        /* for each row of S and of S_inv, excepted the last block */
        for (i = 0, iq = 0; iq < outloopbound; ++iq)
        {
            for (ir = 0; ir < NB_BITS_UINT; ++ir, ++i)
            {
                /* The element of the diagonal is 1 */
                Sinv_cpi.setXor(iq, 1L << ir);
                Sinv_cpj.changeIndex(Sinv_cpi);
                L_cpj.changeIndex(L);
                /* for the next rows */
                for (j = i; j < innerloopbound; ++j)
                {
                    /* next row */
                    Sinv_cpj.move(nextrow);
                    L_cpj.move((j >>> 6) + 1);
                    mask = (-((L_cpj.get() >>> ir) & 1L));
                    for (k = 0; k <= iq; ++k)
                    {
                        //XORLOADMASK1_1(Sinv_cpj + k, Sinv_cpi + k, mask);
                        Sinv_cpj.setXor(k, Sinv_cpi.get(k) & mask);
                    }
                }
                /* Next row */
                Sinv_cpi.move(nextrow);
                L.move(iq + 1);
            }
            /* Next column */
            L.moveIncremental();
        }
        if (ifCondition > 1)
        {
            for (ir = 0; ir < (ifCondition - 1); ++ir, ++i)
            {
                /* The element of the diagonal is 1 */
                Sinv_cpi.setXor(iq, 1L << ir);
                Sinv_cpj.changeIndex(Sinv_cpi);
                L_cpj.changeIndex(L);
                /* for the next rows */
                for (j = i; j < innerloopbound; ++j)
                {
                    /* next row */
                    Sinv_cpj.move(nextrow);
                    L_cpj.move((j >>> 6) + 1);

                    mask = (-((L_cpj.get() >>> ir) & 1L));
                    for (k = 0; k <= iq; ++k)
                    {
                        //XORLOADMASK1_1(Sinv_cpj + k, Sinv_cpi + k, mask);
                        Sinv_cpj.setXor(k, Sinv_cpi.get(k) & mask);
                    }
                }
                /* Next row */
                Sinv_cpi.move(nextrow);
                L.move(iq + 1);
            }

            /* ir = HFEnvr-1 */
            Sinv_cpi.setXor(iq, 1L << ir);
            Sinv_cpi.move(nextrow);
        }
        else if (ifCondition == 1)
        {
            /* ir = 0 */
            Sinv_cpi.set(iq, 1);
            Sinv_cpi.move(nextrow);
        }
        /* Here, Sinv_cpi is at the end of S_inv */
        /* End of U */
        U.move(endOfU);
        /* for each row excepted the first */
        for (i = innerloopbound; i > 0; --i)
        {
            /* Previous row */
            U.move(-1 - (i >>> 6));
            /* Row i of Sinv */
            Sinv_cpi.move(-nextrow);
            /* Row j of Sinv */
            Sinv_cpj.changeIndex(S);
            /* for the previous rows */
            for (j = 0; j < i; ++j)
            {
                /* pivot */
                mask = -(((U.get(j >>> 6)) >>> (j & 63)) & 1);
                xorLoadMask(Sinv_cpj, Sinv_cpi, mask, nextrow);
                /* next row */
                Sinv_cpj.move(nextrow);
            }
        }
    }

    private void xorLoadMask(Pointer C, Pointer A, long mask, int loop)
    {
        for (int i = 0; i < loop; ++i)
        {
            C.setXor(i, A.get(i) & mask);
        }
    }

    enum FunctionParams
    {NV, NVN, V, N, M, NVN_Start}

    void vecMatProduct(Pointer res, Pointer vec, Pointer S_orig, int start, FunctionParams vecMatProduct)
    {
        //vecn_gf2 res, cst_vecn_gf2 vec, cst_Mn_gf2 S, unsigned int start
        int gf2_len, S_cp_increase, loopir_param, nq;
        long bit_ir, vec_ir;
        int iq = 0, ir = 0;
        Pointer S = new Pointer(S_orig);
        switch (vecMatProduct)
        {
        case NV:
            //VECMATPROD(PREFIX_NAME(vecMatProductnv_64),set0_gf2nv,LOOPIR_NV,REM_NV,HFEnvq)
            res.setRangeClear(0, NB_WORD_GF2nv);
            nq = HFEnvq;
            gf2_len = NB_WORD_GF2nv;
            S_cp_increase = NB_WORD_GF2nv;
            break;
        case NVN:
            //VECMATPROD(PREFIX_NAME(vecMatProductnvn_64),set0_gf2n,LOOPIR_N,REM_NV,HFEnvq)
            res.setRangeClear(0, NB_WORD_GFqn);
            gf2_len = NB_WORD_GFqn;
            S_cp_increase = NB_WORD_GFqn;
            nq = HFEnvq;
            break;
        case V:
            //VECMATPROD(PREFIX_NAME(vecMatProductv_64),set0_gf2n,LOOPIR_N,REM_V,HFEvq)
            res.setRangeClear(0, NB_WORD_GFqn);
            gf2_len = NB_WORD_GFqn;
            S_cp_increase = NB_WORD_GFqn;
            nq = HFEvq;
            break;
        case N:
            //VECMATPROD(PREFIX_NAME(vecMatProductn_64),set0_gf2n,LOOPIR_N,REM_N,HFEnq)
            res.setRangeClear(0, NB_WORD_GFqn);
            gf2_len = NB_WORD_GFqn;
            S_cp_increase = NB_WORD_GFqn;
            nq = HFEnq;
            break;
        case M:
            //VECMATPROD(PREFIX_NAME(vecMatProductm_64),set0_gf2m,LOOPIR_M,REM_M,HFEnq)
            res.setRangeClear(0, NB_WORD_GF2m);
            nq = HFEnq;
            gf2_len = NB_WORD_GF2m;
            S_cp_increase = NB_WORD_GFqn;
            break;
        case NVN_Start:
            //VECMATPROD_START(PREFIX_NAME(vecMatProductnvn_start_64),set0_gf2n, LOOPIR_START_N,REM_START_NV,HFEnvq)
            res.setRangeClear(0, NB_WORD_GFqn);
            nq = HFEnvq;
            gf2_len = NB_WORD_GFqn;
            S_cp_increase = NB_WORD_GFqn;
            ir = start & 63;
            iq = start >>> 6;
            break;
        default:
            throw new IllegalArgumentException("Invalid input for vecMatProduct");
        }
        /* for each bit of vec excepted the last block */
        for (; iq < nq; ++iq)
        {
            //LOOPIR_START(NB_BITS_UINT);
            if (vecMatProduct != FunctionParams.NVN_Start)
            {
                bit_ir = vec.get(iq);
            }
            else
            {
                bit_ir = vec.get(iq) >>> ir;
            }
            for (; ir < 64; ++ir)
            {
                vec_ir = -(bit_ir & 1L);
                xorLoadMask(res, S, vec_ir, gf2_len);
                /* next row of S */
                S.move(S_cp_increase);
                bit_ir >>>= 1;
            }
            ir = 0;
        }
        /* the last block */
        switch (vecMatProduct)
        {
        case NV:
            //VECMATPROD(PREFIX_NAME(vecMatProductnv_64),set0_gf2nv,LOOPIR_NV,REM_NV,HFEnvq)
        case NVN:
            //VECMATPROD(PREFIX_NAME(vecMatProductnvn_64),set0_gf2n,LOOPIR_N,REM_NV,HFEnvq)
            if (HFEnvr == 0)
            {
                return;
            }
            bit_ir = vec.get(HFEnvq);
            loopir_param = HFEnvr;
            break;
        case V:
            //VECMATPROD(PREFIX_NAME(vecMatProductv_64),set0_gf2n,LOOPIR_N,REM_V,HFEvq)
            if (HFEvr == 0)
            {
                return;
            }
            bit_ir = vec.get(HFEvq);
            loopir_param = HFEvr;
            break;
        case N:
        case M:
            //VECMATPROD(PREFIX_NAME(vecMatProductm_64),set0_gf2m,LOOPIR_M,REM_M,HFEnq)
            //VECMATPROD(PREFIX_NAME(vecMatProductn_64),set0_gf2n,LOOPIR_N,REM_N,HFEnq)
//            if (HFEnr == 0)
//            {
//                return;
//            }
            bit_ir = vec.get(HFEnq);
            loopir_param = HFEnr;
            break;
        case NVN_Start:
            //VECMATPROD_START(PREFIX_NAME(vecMatProductnvn_start_64),set0_gf2n, LOOPIR_START_N,REM_START_NV,HFEnvq)
            if (HFEnvr == 0)
            {
                return;
            }
            bit_ir = vec.get(HFEnvq) >>> ir;
            loopir_param = HFEnvr;
            break;
        default:
            throw new IllegalArgumentException("Invalid input for vecMatProduct");
        }
        for (; ir < loopir_param; ++ir)
        {
            vec_ir = -(bit_ir & 1);
            xorLoadMask(res, S, vec_ir, gf2_len);
            /* next row of S */
            S.move(S_cp_increase);
            bit_ir >>>= 1;
        }
        if (vecMatProduct == FunctionParams.M && HFEmr != 0)
        {
            res.setAnd(NB_WORD_GF2m - 1, MASK_GF2m);
        }
    }

    /**
     * @return The constant c of pk2, in GF(2).
     * @brief Decompression of a compressed MQ equation in GF(2)[x1,...,x_(n+v)].
     * Both use a lower triangular matrix.
     * @details pk = (c,Q), with c the constant part in GF(2) and Q is a lower
     * triangular matrix of size (n+v)*(n+v) in GF(2). pk2 will have the same
     * format, but the equation will be decompressed. Here, the last byte of pk is
     * padded with null bits.
     * @param[in] pk  A MQ equation in GF(2)[x1,...,x_(n+v)].
     * @param[out] pk2_orig A MQ equation in GF(2)[x1,...,x_(n+v)].
     * @remark Requires to allocate NB_WORD_UNCOMP_EQ 64-bit words for pk2.
     * @remark Requirement: at least NB_BYTES_EQUATION
     * + ((8-(NB_BYTES_EQUATION mod 8)) mod 8) bytes have to be allocated for pk
     * (because pk is casted in 64-bit, and the last memory access requires that
     * is allocated a multiple of 64 bits).
     * @remark Constant-time implementation.
     */
    private long convMQ_uncompressL_gf2(Pointer pk2_orig, PointerUnion pk)
    {
        int iq, ir, k, nb_bits;
        PointerUnion pk64 = new PointerUnion(pk);
        Pointer pk2 = new Pointer(pk2_orig);
        nb_bits = 1;
        pk2_orig.indexReset();
        /* For each row */
        for (iq = 0; iq < HFEnvq; ++iq)
        {
            for (ir = 1; ir < 64; ++ir)
            {
                if ((nb_bits & 63) != 0)
                {
                    for (k = 0; k < iq; ++k)
                    {
                        pk2.set(k, pk64.get(k) >>> (nb_bits & 63) ^ (pk64.get(k + 1) << (64 - (nb_bits & 63))));
                    }
                    pk2.set(k, pk64.get(k) >>> (nb_bits & 63));
                    if (((nb_bits & 63) + ir) > 64)
                    {
                        pk2.setXor(k, pk64.get(k + 1) << (64 - (nb_bits & 63)));
                    }
                    if (((nb_bits & 63) + ir) >= 64)
                    {
                        pk64.moveIncremental();
                    }
                }
                else
                {
                    for (k = 0; k <= iq; ++k)
                    {
                        pk2.set(k, pk64.get(k));
                    }
                }
                pk64.move(iq);
                /* 0 padding on the last word */
                pk2.setAnd(iq, (1L << ir) - 1L);
                pk2.move(iq + 1);
                nb_bits += (iq << 6) + ir;
            }

            /* ir=64 */
            if ((nb_bits & 63) != 0)
            {
                for (k = 0; k <= iq; ++k)
                {
                    pk2.set(k, (pk64.get(k) >>> (nb_bits & 63)) ^ (pk64.get(k + 1) << (64 - (nb_bits & 63))));
                }
            }
            else
            {
                for (k = 0; k <= iq; ++k)
                {
                    pk2.set(k, pk64.get(k));
                }
            }
            pk64.move(iq + 1);
            pk2.move(iq + 1);
            nb_bits += (iq + 1) << 6;
        }
        if (HFEnvr != 0)
        {
            for (ir = 1; ir <= HFEnvr; ++ir)
            {
                if ((nb_bits & 63) != 0)
                {
                    for (k = 0; k < iq; ++k)
                    {
                        pk2.set(k, (pk64.get(k) >>> (nb_bits & 63)) ^ (pk64.get(k + 1) << (64 - (nb_bits & 63))));
                    }
                    pk2.set(k, pk64.get(k) >>> (nb_bits & 63));
                    if (((nb_bits & 63) + ir) > 64)
                    {
                        pk2.setXor(k, pk64.get(k + 1) << (64 - (nb_bits & 63)));
                    }

                    if (((nb_bits & 63) + ir) >= 64)
                    {
                        pk64.moveIncremental();
                    }
                }
                else
                {
                    for (k = 0; k <= iq; ++k)
                    {
                        pk2.set(k, pk64.get(k));
                    }
                }
                pk64.move(iq);
                /* 0 padding on the last word */
                pk2.setAnd(iq, (1L << ir) - 1L);
                pk2.move(iq + 1);
                nb_bits += (iq << 6) + ir;
            }
        }
        /* Constant */
        return pk.get() & 1;
    }

    /**
     * @return The constant c of pk2, in GF(2).
     * @brief Decompression of a compressed MQ equation in GF(2)[x1,...,x_(n+v)].
     * Both use a lower triangular matrix.
     * @details pk = (c,Q), with c the constant part in GF(2) and Q is a lower
     * triangular matrix of size (n+v)*(n+v) in GF(2). pk2 will have the same
     * format, but the equation will be decompressed. Here, the last bits of pk
     * are missing (cf. the output of convMQ_last_UL_gf2). Moreover, the last byte
     * of pk is padded with null bits.
     * @param[in] pk  A MQ equation in GF(2)[x1,...,x_(n+v)].
     * @param[out] pk2 A MQ equation in GF(2)[x1,...,x_(n+v)].
     * @remark Requires to allocate NB_WORD_UNCOMP_EQ 64-bit words for pk2.
     * @remark This function is a modified copy of convMQ_uncompressL_gf2.
     * @remark Constant-time implementation.
     */
    private long convMQ_last_uncompressL_gf2(Pointer pk2, PointerUnion pk)
    {
        PointerUnion pk64 = new PointerUnion(pk);
        int iq, ir, k, nb_bits;
        nb_bits = 1;
        Pointer pk2_orig = new Pointer(pk2);
        pk2_orig.indexReset();
        final int HFEnvqm1 = (HFEnv - 1) >>> 6;
        /* For each row */
        for (iq = 0; iq < HFEnvqm1; ++iq)
        {
            for (ir = 1; ir < 64; ++ir)
            {
                if ((nb_bits & 63) != 0)
                {
                    for (k = 0; k < iq; ++k)
                    {
                        pk2.set(k, (pk64.get(k) >>> (nb_bits & 63)) ^ (pk64.get(k + 1) << (64 - (nb_bits & 63))));
                    }
                    pk2.set(k, pk64.get(k) >>> (nb_bits & 63));
                    if (((nb_bits & 63) + ir) > 64)
                    {
                        pk2.setXor(k, pk64.get(k + 1) << (64 - (nb_bits & 63)));
                    }
                    if (((nb_bits & 63) + ir) >= 64)
                    {
                        pk64.moveIncremental();
                    }
                }
                else
                {
                    for (k = 0; k <= iq; ++k)
                    {
                        pk2.set(k, pk64.get(k));
                    }
                }
                pk64.move(iq);
                /* 0 padding on the last word */
                pk2.setAnd(iq, (1L << ir) - 1L);
                pk2.move(iq + 1);
                nb_bits += (iq << 6) + ir;
            }
            /* ir=64 */
            if ((nb_bits & 63) != 0)
            {
                for (k = 0; k <= iq; ++k)
                {
                    pk2.set(k, (pk64.get(k) >>> (nb_bits & 63)) ^ (pk64.get(k + 1) << (64 - (nb_bits & 63))));
                }
            }
            else
            {
                for (k = 0; k <= iq; ++k)
                {
                    pk2.set(k, pk64.get(k));
                }
            }
            pk64.move(iq + 1);
            pk2.move(iq + 1);
            nb_bits += (iq + 1) << 6;
        }
        final int HFEnvrm1 = (HFEnv - 1) & 63;
        if (HFEnvrm1 != 0)
        {
            for (ir = 1; ir <= HFEnvrm1; ++ir)
            {
                if ((nb_bits & 63) != 0)
                {
                    for (k = 0; k < iq; ++k)
                    {
                        pk2.set(k, (pk64.get(k) >>> (nb_bits & 63)) ^ (pk64.get(k + 1) << (64 - (nb_bits & 63))));
                    }
                    pk2.set(k, pk64.get(k) >>> (nb_bits & 63));
                    if (((nb_bits & 63) + ir) > 64)
                    {
                        pk2.setXor(k, pk64.get(k + 1) << (64 - (nb_bits & 63)));
                    }

                    if (((nb_bits & 63) + ir) >= 64)
                    {
                        pk64.moveIncremental();
                    }
                }
                else
                {
                    for (k = 0; k <= iq; ++k)
                    {
                        pk2.set(k, pk64.get(k));
                    }
                }
                pk64.move(iq);
                /* 0 padding on the last word */
                pk2.setAnd(iq, (1L << ir) - 1L);
                pk2.move(iq + 1);
                nb_bits += (iq << 6) + ir;
            }
        }
        /* Last row */
        /* The size of the last row is HFEnv-LOST_BITS bits */
        final int LAST_ROW_Q = ((HFEnv - LOST_BITS) >>> 6);
        final int LAST_ROW_R = ((HFEnv - LOST_BITS) & 63);
        iq = LAST_ROW_Q;
//        if ((((NB_MONOMIAL_PK - LOST_BITS + 7) >>>3) & 7) != 0)
//        {
        //PointerUnion pk_end;
        long end;
//        }
        if (LAST_ROW_R != 0)
        {
            ir = LAST_ROW_R;
            if ((nb_bits & 63) != 0)
            {
                if ((((NB_MONOMIAL_PK - LOST_BITS + 7) >>> 3) & 7) != 0)
                {
                    final int NB_WHOLE_BLOCKS = ((HFEnv - ((64 - ((NB_MONOMIAL_PK - LOST_BITS - HFEnvr) & 63)) & 63)) >>> 6);
                    for (k = 0; k < NB_WHOLE_BLOCKS; ++k)
                    {
                        pk2.set(k, (pk64.get(k) >>> (nb_bits & 63)) ^ (pk64.getWithCheck(k + 1) << (64 - (nb_bits & 63))));
                    }
                    pk2.set(k, pk64.getWithCheck(k) >>> (nb_bits & 63));
                    if (NB_WHOLE_BLOCKS < LAST_ROW_Q)
                    {
                        end = pk64.getWithCheck(k + 1);
                        pk2.setXor(k, end << (64 - (nb_bits & 63)));
                        pk2.set(k + 1, end >>> (nb_bits & 63));
                    }
                    else
                    {
                        if (((nb_bits & 63) + ir) > 64)
                        {
                            pk2.setXor(k, pk64.getWithCheck(k + 1) << (64 - (nb_bits & 63)));
                        }
                    }
                }
                else
                {
                    for (k = 0; k < iq; ++k)
                    {
                        pk2.set(k, (pk64.get(k) >>> (nb_bits & 63)) ^ (pk64.get(k + 1) << (64 - (nb_bits & 63))));
                    }
                    pk2.set(k, pk64.get(k) >>> (nb_bits & 63));
                    if (((nb_bits & 63) + ir) > 64)
                    {
                        pk2.setXor(k, pk64.get(k + 1) << (64 - (nb_bits & 63)));
                    }
                }
            }
            else
            {
                if ((((NB_MONOMIAL_PK - LOST_BITS + 7) >>> 3) & 7) != 0)
                {
                    for (k = 0; k < iq; ++k)
                    {
                        pk2.set(k, pk64.get(k));
                    }
                    pk2.set(k, pk64.getWithCheck(k));
                }
                else
                {
                    for (k = 0; k <= iq; ++k)
                    {
                        pk2.set(k, pk64.get(k));
                    }
                }
            }
        }
        else if (LAST_ROW_Q != 0)
        {
            if ((nb_bits & 63) != 0)
            {
                if ((((NB_MONOMIAL_PK - LOST_BITS + 7) >>> 3) & 7) != 0)
                {
                    for (k = 0; k < (iq - 1); ++k)
                    {
                        pk2.set(k, (pk64.get(k) >>> (nb_bits & 63)) ^ (pk64.get(k + 1) << (64 - (nb_bits & 63))));
                    }
                    pk2.set(k, pk64.get(k) >>> (nb_bits & 63));
                    pk2.setXor(k, pk64.getWithCheck(k + 1) << (64 - (nb_bits & 63)));
                }
                else
                {
                    for (k = 0; k < iq; ++k)
                    {
                        pk2.set(k, (pk64.get(k) >>> (nb_bits & 63)) ^ (pk64.get(k + 1) << (64 - (nb_bits & 63))));
                    }
                }
            }
            else
            {
                for (k = 0; k < iq; ++k)
                {
                    pk2.set(k, pk64.get(k));
                }
            }
        }
        Pointer pkPrint = new Pointer(pk2);
        pkPrint.indexReset();
        /* Constant */
        return pk.get() & 1L;
    }

    /**
     * @return 0 for a valid signature, !=0 else.
     * @brief Verify the signature of the document m of length len bytes, using a
     * (HFEv-)-based signature scheme. pk can be evaluated with the eval_pk
     * function, and hpk is used during this evaluation.
     * @details eval_pk takes 4 arguments here.
     * @param[in] m   A pointer on a document.
     * @param[in] len The length in bytes of the document m.
     * @param[in] sm8 A signature generated by a (HFEv-)-based signature scheme.
     * @param[in] pk  The original public-key, a MQ system with m equations in
     * GF(2)[x1,...,x_(n+v)].
     * @param[in] hpk The hybrid representation of one part of the public-key pk.
     * @remark Requirement: when SSE or AVX is enabled, the public-key must be
     * aligned respectively on 16 or 32 bytes. However, this requirement and the
     * alignment are disabled for the public/stable version of MQsoft (to be simple
     * to use, generic for the allocation of pk and to avoid segmentation faults).
     * @remark This function does not require a constant-time implementation.
     */
    public int sign_openHFE_huncomp_pk(byte[] m, int len, byte[] sm8, PointerUnion pk, PointerUnion hpk)
    {
        Pointer sm = new Pointer(SIZE_SIGN_UNCOMPRESSED - SIZE_SALT_WORD);
        int m_cp = 0, sm8_cp = 0;
        Pointer Si_tab = new Pointer(NB_WORD_GF2nv);
        Pointer Si1_tab = new Pointer(NB_WORD_GF2nv);
        long cst = 0; //if HFEmr8
        /* Copy of pointer */
        Pointer tmp;
        Pointer Si = new Pointer(Si_tab);
        Pointer Si1 = new Pointer(Si1_tab);
        /* Vector of D_1, ..., D_(NB_ITE) */
        PointerBuffer D = new PointerBuffer(NB_ITE * SIZE_DIGEST_UINT, 64);
        //PointerUnion D64 = new PointerUnion(NB_ITE * SIZE_DIGEST_UINT);
        int i;
        int index;//if (HFEnv != HFEm)
        if (HFEmr8 != 0)
        {
            cst = hpk.get();
            /* We jump the constant (stored on 8 bytes) */
            //hpk += 8;
            hpk.move(1);
        }
//    #if EUF_CMA_PROPERTY
//        sm8 += SIZE_SALT;
//    #endif
        if (NB_ITE == 1)
        {
            /* Take the (n+v) first bits */
            System.arraycopy(sm8, 0, sm.toBytes(NB_BYTES_GFqnv), 0, NB_BYTES_GFqnv);
        }
        else
        {
            uncompress_signHFE(sm, sm8, 0);
        }

        SHA3Digest sha3Digest = new SHA3Digest(Sha3BitStrength);//256?
        if (EUF_CMA_PROPERTY)
        {
            byte[] Hd = new byte[SIZE_DIGEST_UINT + SIZE_SALT_WORD];//(SIZE_DIGEST_UINT + SIZE_SALT_WORD)<<1?
            /* Compute H(m) */
            sha3Digest.update(m, m_cp, len);
            sha3Digest.doFinal(Hd, 0);
            /* H(m)||r */
            sm8_cp -= SIZE_SALT;
            System.arraycopy(sm8, sm8_cp, Hd, SIZE_DIGEST_UINT, SIZE_SALT_WORD);
            /* Compute H1 = H(H(m)||r) */
            sha3Digest.reset();
            sha3Digest.update(Hd, 0, SIZE_DIGEST + SIZE_SALT);
            sha3Digest.doFinal(D.getBuffer(), 0);
            D.bufferFill(0);
        }
        else
        {
            /* Compute H1 = H(m), the m first bits are D1 */
            sha3Digest.update(m, m_cp, len);
            sha3Digest.doFinal(D.getBuffer(), 0);
            D.bufferFill(0);
        }

        for (i = 1; i < NB_ITE; ++i)
        {
            /* Compute Hi = H(H_(i-1)), the m first bits are Di */
            sha3Digest.reset();
            sha3Digest.update(D.getBuffer(), 0, SIZE_DIGEST);//(i - 1) * SIZE_DIGEST_UINT
            sha3Digest.doFinal(D.getBuffer(), 0);//i * SIZE_DIGEST_UINT
            D.bufferFill(i * SIZE_DIGEST_UINT);
            /* Clean the previous hash (= extract D_(i-1) from H_(i-1)) */
            if (HFEmr != 0)
            {
                D.setAnd(SIZE_DIGEST_UINT * (i - 1) + NB_WORD_GF2m - 1, MASK_GF2m);
            }
        }
        /* Clean the previous hash (= extract D_(i-1) from H_(i-1)) */
        if (HFEmr != 0)
        {
            D.setAnd(SIZE_DIGEST_UINT * (i - 1) + NB_WORD_GF2m - 1, MASK_GF2m);
        }
        /* Compute p(S_(NB_IT),X_(NB_IT)) */
        //TODO: bug when HFEmr8 is 0 use evalMQSnocst8_gf2 (evalMQSnocst8_unrolled_gf2) function
        evalMQShybrid8_uncomp_nocst_gf2_m(Si, sm, pk, hpk);
        if (HFEmr8 != 0)
        {
            Si.setXor(HFEmq, cst);
        }
//    #ifdef KAT_INT
//        fprintf(fp, "i=%u\n", NB_ITE);
//        fprintBstr_KAT_INT(fp, "xor(Di,S_(i-1)): ", (unsigned char*)Si,
//        NB_BYTES_GFqm);
//    #endif
        for (i = NB_ITE - 1; i > 0; --i)
        {
//        #ifdef KAT_INT
//            fprintf(fp, "i=%u\n", i);
//        #endif
            /* Compute Si = xor(p(S_i+1,X_i+1),D_i+1) */
            Si.setXorRange(0, D, i * SIZE_DIGEST_UINT, NB_WORD_GF2m);
//            if (HFEnv != HFEm)
//            {
            /* Compute Si||Xi */
            index = NB_WORD_GF2nv + (NB_ITE - 1 - i) * NB_WORD_GF2nvm;
            if (HFEmr != 0)
            {
                Si.setAnd(NB_WORD_GF2m - 1, MASK_GF2m);
                /* Concatenation(Si,Xi): the intersection between S1 and X1 is not null */
                Si.setXor(NB_WORD_GF2m - 1, sm.get(index));
                if (NB_WORD_GF2nvm != 1)
                {
                    ++index;
                    Si.copyFrom(NB_WORD_GF2m, sm, index, NB_WORD_GF2nvm - 1);
                    //copy_gf2nvm1(Si + NB_WORD_GF2m, sm + index);
                }
            }
            else
            {
                /* Concatenation(Si,Xi) */
                Si.copyFrom(NB_WORD_GF2m, sm, index, NB_WORD_GF2nvm);
                //copy_gf2nvm(Si + NB_WORD_GF2m, sm + index);
            }
            //}
//        #ifdef KAT_INT
//            fprintBstr_KAT_INT(fp, "Si||Xi: ", (unsigned char*)Si, NB_BYTES_GFqnv);
//        #endif
            /* Compute p(Si,Xi) */
            //eval_pk(Si1, Si, pk, hpk);
            evalMQShybrid8_uncomp_nocst_gf2_m(Si1, Si, pk, hpk);
            if (HFEmr8 != 0)
            {
                Si1.setXor(HFEmq, cst);
            }
            /* Permutation of pointers */
            tmp = new Pointer(Si1);
            Si1.changeIndex(Si);
            Si.changeIndex(tmp);
//        #ifdef KAT_INT
//            fprintBstr_KAT_INT(fp, "xor(Di,S_(i-1)): ", (unsigned char*)Si,
//            NB_BYTES_GFqm);
//        #endif
        }
//
//    #ifdef KAT_INT
//        fprintBstr_KAT_INT(fp, "true D1: ", (unsigned char*)D, NB_BYTES_GFqm);
//        CLOSE_KAT_INT_FILE;
//    #endif
//
//        /* D1'' == D1 */
        return isEqual_nocst_gf2(Si, D, NB_WORD_GF2m) ? 1 : 0;

    }

    /**
     * @brief Variable-time evaluation of a MQS in a vector. The MQS is stored
     * with a hybrid representation.
     * @details The FORMAT_HYBRID_CPK8 have to be used. The (m-(m mod 8)) first
     * equations are stored as one multivariate quadratic equation in
     * GF(2^(m-(m mod 8)))[x1,...,x_(n+v)], i.e. the monomial representation is
     * used. This corresponds to mq_quo. The (m mod 8) last equations are stored
     * separately in mq_rem. Here, the EVAL_HYBRID_CPK8_UNCOMP have to be used, i.e.
     * the last equations are uncompressed.
     * mq_quo = (c',Q').
     * mq_rem = (c_(m-(m mod 8)),Q_(m-(m mod 8)),...,c_(m-1),Q_(m-1)).
     * c' is in GF(2^(m-(m mod 8))).
     * Q' is upper triangular of size (n+v)*(n+v) in GF(2^(m-(m mod 8))).
     * The (m mod 8) ci are in GF(2).
     * The (m mod 8) Qi are lower triangular of size (n+v)*(n+v) in GF(2).
     * For each Qi, the rows are stored separately (we take new words for each new
     * row).
     * @param[in] x   A vector of n+v elements in GF(2).
     * @param[in] mq_quo  The (m-(m mod 8)) first equations,
     * in GF(2^(m-(m mod 8)))[x1,...,x_(n+v)].
     * @param[in] mq_rem_orig  The (m mod 8) last equations,
     * in (GF(2)[x1,...,x_(n+v)])^(m mod 8).
     * @param[out] res A vector of m elements in GF(2), evaluation of the MQS in x.
     * @remark Requirement: at least ACCESS_last_equations8 + ((8-(HFEmq8 mod 8))
     * mod 8) bytes have to be allocated for mq_quo (because of the use of
     * evalMQSnocst8_quo_gf2).
     * @remark If a vector version of evalMQnocst_gf2 is used, maybe the last
     * vector load read outside of memory. So, if this load reads z bits, let
     * B be ceiling(z/64). The last equation requires NB_WORD_UNCOMP_EQ
     * + ((B-(NB_WORD_GF2nv mod B)) mod B) 64-bit words.
     * @remark Variable-time implementation.
     */
    private void evalMQShybrid8_uncomp_nocst_gf2_m(Pointer res, Pointer x, PointerUnion mq_quo, PointerUnion mq_rem_orig)
    {
        PointerUnion mq_rem = new PointerUnion(mq_rem_orig);
        if (HFEmq8 != 0)
        {
            evalMQSnocst8_quo_gf2(res, x, mq_quo);
        }

        if (HFEmr8 != 0)
        {
            if (HFEmr < 8)
            {
                res.set(HFEmq, 0);
            }
            int i;
            for (i = HFEmr - HFEmr8; i < HFEmr; ++i)
            {
                res.setXor(HFEmq, evalMQnocst_unrolled_no_simd_gf2(x, mq_rem) << i);
                mq_rem.move(NB_WORD_UNCOMP_EQ);
            }
        }
    }

    /* Uncompress the signature */
    private void uncompress_signHFE(Pointer sm, byte[] sm8, int sm8_cp)
    {
        PointerUnion sm64 = new PointerUnion(sm);
        int k2;
        /* Take the (n+v) first bits */
        sm64.fillBytes(0, sm8, sm8_cp, NB_BYTES_GFqnv);
        /* Clean the last byte */
        if ((NB_ITE > 1) && HFEnvr8 != 0)
        {
            sm64.setAndByte(NB_BYTES_GFqnv - 1, (byte)MASK8_GF2nv);
        }
        /* Take the (Delta+v)*(nb_ite-1) bits */
        if (NB_ITE > 1)//(NB_ITE > 1) || HFEDELTA + HFEv == 0
        {
            int k1, nb_bits, nb_rem2, nb_rem_m, val_n;
            //if (HFEmr8)
            int nb_rem;
            /* HFEnv bits are already extracted from sm8 */
            nb_bits = HFEnv;
            sm64.moveNextBytes((NB_WORD_GF2nv << 3) + (HFEmq8 & 7));
            for (k1 = 1; k1 < NB_ITE; ++k1)
            {
                /* Number of bits to complete the byte of sm8, in [0,7] */
                val_n = Math.min((HFEDELTA + HFEv), ((8 - (nb_bits & 7)) & 7));
                /* First byte of sm8 */
                if ((nb_bits & 7) != 0)
                {
                    if (HFEmr8 != 0)
                    {
                        sm64.setXorByte((byte)(((sm8[nb_bits >>> 3] & 0xFF) >>> (nb_bits & 7)) << HFEmr8));
                        /* Number of bits to complete the first byte of sm8 */
                        nb_rem = val_n - VAL_BITS_M;
                        if (nb_rem >= 0)
                        {
                        /* We take the next byte since we used
                           VAL_BITS_M bits */
                            sm64.moveNextByte();
                        }
                        if (nb_rem > 0)
                        {
                            nb_bits += VAL_BITS_M;
                            sm64.setXorByte((byte)((sm8[nb_bits >>> 3] & 0xFF) >>> (nb_bits & 7)));
                            nb_bits += nb_rem;
                        }
                        else
                        {
                            nb_bits += val_n;
                        }
                    }
                    else
                    {
                        /* We can take 8 bits, and we want at most 7 bits. */
                        sm64.setByte((byte)((sm8[nb_bits >>> 3] & 0xFF) >>> (nb_bits & 7)));
                        nb_bits += val_n;
                    }
                }
                /* Other bytes of sm8 */
                nb_rem2 = (HFEDELTA + HFEv) - val_n;
                /*nb_rem2 can be zero only in this case */
//                if ((HFEDELTA + HFEv) >= 8 || nb_rem2 != 0)
//                {
                /* Number of bits used of sm64, mod 8 */
                nb_rem_m = (HFEm + val_n) & 7;
                /* Other bytes */
                if (nb_rem_m != 0)
                {
                    /* -1 to take the ceil of /8, -1 */
                    for (k2 = 0; k2 < ((nb_rem2 - 1) >>> 3); ++k2)
                    {
                        sm64.setXorByte((byte)((sm8[nb_bits >>> 3] & 0xFF) << nb_rem_m));
                        sm64.moveNextByte();
                        sm64.setXorByte((byte)((sm8[nb_bits >>> 3] & 0xFF) >>> (8 - nb_rem_m)));

                        nb_bits += 8;
                    }
                    /* The last byte of sm8, between 1 and 8 bits to put */
                    sm64.setXorByte((byte)((sm8[nb_bits >>> 3] & 0xFF) << nb_rem_m));
                    sm64.moveNextByte();
                    /* nb_rem2 between 1 and 8 bits */
                    nb_rem2 = ((nb_rem2 + 7) & 7) + 1;
                    if (nb_rem2 > (8 - nb_rem_m))
                    {
                        sm64.setByte((byte)((sm8[nb_bits >>> 3] & 0xFF) >>> (8 - nb_rem_m)));
                        sm64.moveNextByte();
                    }
                    nb_bits += nb_rem2;
                }
                else
                {
                    /* We are at the beginning of the bytes of sm8 and sm64 */
                    /* +7 to take the ceil of /8 */
                    for (k2 = 0; k2 < ((nb_rem2 + 7) >>> 3); ++k2)
                    {
                        sm64.setByte(sm8[nb_bits >>> 3]);
                        nb_bits += 8;
                        sm64.moveNextByte();
                    }
                    /* The last byte has AT MOST 8 bits. */
                    nb_bits -= (8 - (nb_rem2 & 7)) & 7;
                }
//                }
//                else if ((HFEDELTA + HFEv) < 8)
//                {
//                    sm64.moveNextByte();
//                }
                /* Clean the last byte */
                if (HFEnvr8 != 0)
                {
                    sm64.setAndByte(-1, (byte)MASK8_GF2nv);
                }
                /* We complete the word. Then we search the first byte. */
                sm64.moveNextBytes(((8 - (NB_BYTES_GFqnv & 7)) & 7) + (HFEmq8 & 7));
            }
        }
    }

    private void evalMQSnocst8_quo_gf2(Pointer c, Pointer m, PointerUnion pk_orig)
    {
        long xi, xj;
        int iq, ir, i = HFEnv, jq;
        final int NB_EQ = (HFEm >>> 3) != 0 ? ((HFEm >>> 3) << 3) : HFEm;
        final int NB_BYTES_EQ = (NB_EQ & 7) != 0 ? ((NB_EQ >>> 3) + 1) : (NB_EQ >>> 3);
        final int NB_WORD_EQ = (NB_BYTES_EQ >>> 3) + ((NB_BYTES_EQ & 7) != 0 ? 1 : 0);//getNB_WORD_EQFromNB_BYTES_EQ(NB_BYTES_EQ);
        //if (LEN_UNROLLED_64!=1)
        //int h;
        /* Constant cst_pk */
        //COPY_64bits_variables(c, (const UINT *)pk);
        PointerUnion pk = new PointerUnion(pk_orig);
        System.arraycopy(pk.getArray(), 0, c.getArray(), c.getIndex(), NB_WORD_EQ);
        pk.moveNextBytes(NB_BYTES_EQ);
        /* for each row of the quadratic matrix of pk, excepted the last block */
        for (iq = 0; iq < HFEnvq; ++iq)
        {
            xi = m.get(iq);
            for (ir = 0; ir < NB_BITS_UINT; ++ir, --i)
            {
                if ((xi & 1) != 0)
                {
                    /* for each column of the quadratic matrix of pk */
                    /* xj=xi=1 */
                    c.setXorRange(0, pk, 0, NB_WORD_EQ);
                    //XOR_ELEM(c, (const UINT *)pk);
                    pk.moveNextBytes(NB_BYTES_EQ);
                    xj = xi >>> 1;
                    LOOPJR_UNROLLED_64(c, pk, ir + 1, NB_BITS_UINT, xj, NB_BYTES_EQ, NB_WORD_EQ);
                    for (jq = iq + 1; jq < HFEnvq; ++jq)
                    {
                        xj = m.get(jq);
                        LOOPJR_UNROLLED_64(c, pk, 0, NB_BITS_UINT, xj, NB_BYTES_EQ, NB_WORD_EQ);
                    }
                    if ((HFEnvr) != 0)
                    {
                        xj = m.get(HFEnvq);
                        if (HFEnvr < (LEN_UNROLLED_64 << 1))
                        {
                            LOOPJR_NOCST_64(c, pk, 0, HFEnvr, xj, NB_BYTES_EQ, NB_WORD_EQ);
                        }
                        else
                        {
                            LOOPJR_UNROLLED_64(c, pk, 0, HFEnvr, xj, NB_BYTES_EQ, NB_WORD_EQ);
                        }
                    }
                }
                else
                {
                    pk.moveNextBytes(i * NB_BYTES_EQ);
                }
                xi >>>= 1;
            }
        }

        /* the last block */
        if (HFEnvr != 0)
        {
            xi = m.get(HFEnvq);
            for (ir = 0; ir < HFEnvr; ++ir, --i)
            {
                if ((xi & 1) != 0)
                {
                    /* for each column of the quadratic matrix of pk */
                    /* xj=xi=1 */
                    //XOR_ELEM(c, (const UINT *)pk);
                    c.setXorRange(0, pk, 0, NB_WORD_EQ);
                    pk.moveNextBytes(NB_BYTES_EQ);
                    xj = xi >>> 1;
                    if (HFEnvr < (LEN_UNROLLED_64 << 1))
                    {
                        LOOPJR_NOCST_64(c, pk, ir + 1, HFEnvr, xj, NB_BYTES_EQ, NB_WORD_EQ);
                        //LOOPJR_NOCST_64(ir + 1, HFEnvr);
                    }
                    else
                    {
                        LOOPJR_UNROLLED_64(c, pk, ir + 1, HFEnvr, xj, NB_BYTES_EQ, NB_WORD_EQ);
                        //LOOPJR_UNROLLED_64(ir + 1, HFEnvr);
                    }
                }
                else
                {
                    pk.moveNextBytes(i * NB_BYTES_EQ);
                }
                xi >>>= 1;
            }
        }
        MASK_64(c, NB_WORD_EQ - 1, NB_EQ);

    }

    private void MASK_64(Pointer c, int p, int NB_EQ)
    {
        if ((NB_EQ & 63) != 0)
        {
            c.setAnd(p, (1L << (NB_EQ & 63)) - 1L);
        }
    }

    private void LOOPJR_UNROLLED_64(Pointer c, PointerUnion pk64, int START, int NB_IT, long xj, int NB_BYTES_EQ, int NB_WORD_EQ)
    {
//        if (LEN_UNROLLED_64 == 1)
//        {
//            return LOOPJR_NOCST_64(c, pk64, START, NB_IT, xj, NB_BYTES_EQ, NB_WORD_EQ);
//        }
        int jr, h;
//        int len = (NB_BYTES_EQ >>> 3) + ((NB_BYTES_EQ & 7) != 0 ? 1 : 0);
        for (jr = START; jr < (NB_IT - LEN_UNROLLED_64 + 1); jr += LEN_UNROLLED_64)
        {
            for (h = 0; h < LEN_UNROLLED_64; ++h)
            {
                if ((xj & 1L) != 0)
                {
                    c.setXorRange(0, pk64, 0, NB_WORD_EQ);
                }
                pk64.moveNextBytes(NB_BYTES_EQ);
                xj >>>= 1;
            }
        }
        for (; jr < NB_IT; ++jr)
        {
            if ((xj & 1L) != 0)
            {
                c.setXorRange(0, pk64, 0, NB_WORD_EQ);
            }
            pk64.moveNextBytes(NB_BYTES_EQ);
            xj >>>= 1;
        }
    }

    private void LOOPJR_NOCST_64(Pointer c, PointerUnion pk64, int START, int NB_IT, long xj, int NB_BYTES_EQ, int NB_WORD_EQ)
    {
        //int len = (NB_BYTES_EQ >>> 3) + ((NB_BYTES_EQ & 7) != 0 ? 1 : 0);
        for (int jr = START; jr < NB_IT; ++jr)
        {
            if ((xj & 1) != 0)
            {
                c.setXorRange(0, pk64, 0, NB_WORD_EQ);
            }
            pk64.moveNextBytes(NB_BYTES_EQ);
            xj >>>= 1;
        }
    }

    private long evalMQnocst_unrolled_no_simd_gf2(Pointer m, PointerUnion mq_orig)
    {
        long acc = 0;
        int i;
        int loop_end = ((NB_WORD_GF2nv == 1) && (HFEnvr != 0)) ? HFEnvr : 64;
        PointerUnion mq = new PointerUnion(mq_orig);
        for (i = 0; i < loop_end; ++i)
        {
            if (((m.get() >>> i) & 1) != 0)
            {
                acc ^= mq.get(i) & m.get();
            }
        }
        mq.move(64);
        for (int j = 1; j < NB_WORD_GF2nv; ++j)
        {
            loop_end = (NB_WORD_GF2nv == (j + 1) && HFEnvr != 0) ? HFEnvr : 64;
            for (i = 0; i < loop_end; ++i)
            {
                if (((m.get(j) >>> i) & 1) != 0)
                {
                    for (int k = 0; k <= j; ++k)
                    {
                        acc ^= mq.get(k) & m.get(k);
                    }
                }
                mq.move(j + 1);
            }
        }
        acc = XORBITS_UINT(acc);
        return acc;
    }

    private long XORBITS_UINT(long n)
    {
        n ^= n >>> 32;
        n ^= n >>> 16;
        n ^= n >>> 8;
        n ^= n >>> 4;
        n ^= n >>> 2;
        n ^= n >>> 1;
        n &= 1L;
        return n;
    }

    private long ORBITS_UINT(long n)
    {
        n |= n >>> 32;
        n |= n >>> 16;
        n |= n >>> 8;
        n |= n >>> 4;
        n |= n >>> 2;
        n |= n >>> 1;
        n &= 1L;
        return n;
    }

    private long NORBITS_UINT(long n)
    {
        n |= n >>> 32;
        n |= n >>> 16;
        n |= n >>> 8;
        n |= n >>> 4;
        n |= n >>> 2;
        n |= n >>> 1;
        n = ~n;
        n &= 1L;
        return n;
    }

    private boolean isEqual_nocst_gf2(Pointer a, Pointer b, int len)
    {
        for (int i = 0; i < len; ++i)
        {
            if (a.get(i) != b.get(i))
            {
                return false;
            }
        }
        return true;
    }

    public int signHFE_FeistelPatarin(SecureRandom random, byte[] sm8, byte[] m, int m_cp, int len, byte[] sk)
    {
        this.random = random;

        Pointer U = new Pointer(NB_WORD_GFqn);
        Pointer Hi_tab = new Pointer(SIZE_DIGEST_UINT);
        Pointer Hi1_tab = new Pointer(SIZE_DIGEST_UINT);
        Pointer tmp = new Pointer();

        Pointer Hi1 = new Pointer(Hi1_tab);
        final int HFEvr8 = HFEv & 7;
        /* Number of bytes that an element of GF(2^(n+v)) needs */
        final int NB_BYTES_GFqv = (HFEv >>> 3) + ((HFEvr8 != 0) ? 1 : 0);
        final long HFE_MASKv = maskUINT(HFEvr);
        int k;
//    #if (HFEnv!=HFEm)
        int index;
//    #if(HFEn>HFEm)

//        #if(HFEm&7)
        long rem_char = 0;//byte or char?
//
        int nb_root;
        SecretKeyHFE sk_HFE = new SecretKeyHFE(this);

        //if(HFEv!=0)
        Pointer F = new Pointer();
        int i;
        Pointer V = new Pointer(NB_WORD_GFqv);
        //if (HFEv!=0 && HFEDeg > 1)
        Pointer tmp_n = new Pointer(NB_WORD_GFqn);
        Pointer[] linear_coefs = new Pointer[HFEDegI + 1];
//        if (HFEDeg > 1)
//        {
        nb_root = precSignHFE(sk_HFE, linear_coefs, sk);
//        }
//        else
//        {
//            nb_root = precSignHFE(sk_HFE, null, sk);
//        }
        if (nb_root != 0)
        {
            /* Error from malloc */
            return nb_root;
        }
//        if (HFEv != 0)
//        {
        F = new Pointer(sk_HFE.F_struct.poly);
//        }
//    #ifdef KAT_INT
//        OPEN_KAT_INT_FILE;
//        fputs("Sign:\n",fp);
//        unsigned int nb_try_to_sign;
//    #endif
        /* Compute H1 = H(m) */
        PointerBuffer Hi = new PointerBuffer(Hi_tab, Sha3BitStrength / 8);

        SHA3Digest sha3Digest = new SHA3Digest(Sha3BitStrength);
        sha3Digest.update(m, m_cp, len);
        sha3Digest.doFinal(Hi.getBuffer(), 0);
        Hi.bufferFill(0);
        /* It is to initialize S0 to 0, because Sk||Xk is stored in sm */
        Pointer sm = new Pointer(SIZE_SIGN_UNCOMPRESSED - SIZE_SALT_WORD);
        Pointer DR = new Pointer(NB_WORD_GF2nv);
        PointerUnion DR_cp = new PointerUnion(DR);

        sm.setRangeClear(0, NB_WORD_GF2nv);
        DR.setRangeClear(0, NB_WORD_GF2nv);

        for (k = 1; k <= NB_ITE; ++k)
        {
//        #ifdef KAT_INT
//            nb_try_to_sign=0U;
//            fprintf(fp,"k=%u\n",k);
//        #endif
            /* Compute xor(D_k,S_(k-1)) */
            DR.setXorRange(sm, Hi, NB_WORD_GF2m);
//        #if AFFINE_TRANSFORMATION_BY_t
//            /* DR - t */
//            add2_gf2m(DR, sk_HFE.t);
//        #endif
            if ((HFEm & 7) != 0)
                /* Clean the last char to compute rem_char (the last word is cleaned) */
            {
                DR.setAnd(NB_WORD_GF2m - 1, MASK_GF2m);
                /* Save the last byte because we need to erase this value by randombytes */
//                if (HFEn > HFEm)
//                {
                rem_char = DR_cp.getByte(NB_BYTES_GFqm - 1);
                //}
            }
//        #ifdef KAT_INT
//            fprintBstr_KAT_INT(fp, "xor(Dk,S_(k-1)): ",
//                (unsigned char*)DR, NB_BYTES_GFqm);
//        #endif
//        #if GEN_MINUS_VINEGARS
//        /* When the root finding fails, the minus and vinegars are regenerated */
            do
            {
//        #endif
//                if (HFEn > HFEm)
//                {
                /* Compute Dk||Rk: add random to have n bits, without erased the m bits */
                if ((HFEm & 7) != 0)
                {
                    /* Generation of Rk */
                    DR_cp.fillRandomBytes(NB_BYTES_GFqm - 1, random, NB_BYTES_GFqn - NB_BYTES_GFqm + 1);
                    /* Put HFEm&7 first bits to 0 */
                    DR_cp.setAndByte(NB_BYTES_GFqm - 1, (byte)-(1 << (HFEm & 7)));//(byte)~((1 << (HFEm & 7)) - 1)
                    /* Store rem_char */
                    DR_cp.setXorByte(NB_BYTES_GFqm - 1, (byte)rem_char);
                }
                else
                {
                    DR_cp.fillRandomBytes(NB_BYTES_GFqm, random, NB_BYTES_GFqn - NB_BYTES_GFqm);
                }

                /* To clean the last char (because of randombytes), the last word is cleaned */
                if ((HFEn & 7) != 0)
                {
                    DR.setAnd(NB_WORD_GFqn - 1, MASK_GF2n);
                }
                //}
//            #ifdef KAT_INT
//                    ++nb_try_to_sign;
//                    fprintf(fp, "Try %u, ", nb_try_to_sign);
//                    fprintBstr_KAT_INT(fp, "Dk||Rk: ", (unsigned char*)DR,
//                    NB_BYTES_GFqn);
//            #endif
                /* Compute Sk||Xk = Inv_p(Dk,Rk) */
                /* Firstly: compute c * T^(-1) */
                vecMatProduct(U, DR, sk_HFE.T, 0, FunctionParams.N);
//        #if (!GEN_MINUS_VINEGARS)
//                    /* When the root finding fails, only the vinegars are regenerated */
//                {
//                    do
//                    {
//        #endif
                /* Secondly: find v with F_HFE(v) = U */
                /* Generation of vinegar variables: v bits */
//                if (HFEv != 0)
//                {
                V.fillRandom(0, random, NB_BYTES_GFqv);
                if (HFEvr8 != 0)
                {
                    /* Clean the last word */
                    V.setAnd(NB_WORD_GFqv - 1, HFE_MASKv);
                }
                /* Evaluation of the constant, quadratic map with v vinegars */
                evalMQSv_gf2(F, V, sk_HFE.F_HFEv);

//                    if (HFEDeg > 1)
//                    {
                /* Evaluation of the linear terms, linear maps with v vinegars */
                if (ENABLED_REMOVE_ODD_DEGREE)
                {
                    //int loop_end=HFEDegI;
//                        if (HFEDegI == HFEDegJ)
//                        {
//                            loop_end = LOG_odd_degree;
//                        }
//                    if (HFEDegI <= LOG_odd_degree)//else if
//                    {
//                        loop_end = HFEDegI;
//                    }
//                    else
//                    {
//                        loop_end = (LOG_odd_degree + 1);
//                    }
                    for (i = 0; i <= HFEDegI; ++i)
                    {
                        vecMatProduct(tmp_n, V, new Pointer(linear_coefs[i], NB_WORD_GFqn), 0, FunctionParams.V);
                        add_gf2(new Pointer(F, NB_WORD_GFqn * (((i * (i + 1)) >>> 1) + 1)), linear_coefs[i], tmp_n);
                    }
//                    for (; i <= HFEDegI; ++i)
//                    {
//                        vecMatProduct(tmp_n, V, new Pointer(linear_coefs[i], NB_WORD_GFqn), 0, FunctionParams.V);
//                        add_gf2(new Pointer(F, NB_WORD_GFqn * (((i * (i - 1)) >>> 1) + 2 + LOG_odd_degree)), linear_coefs[i], tmp_n);
//                    }
                }
                else
                {
                    for (i = 0; i <= HFEDegI; ++i)
                    {
                        vecMatProduct(tmp_n, V, new Pointer(linear_coefs[i], NB_WORD_GFqn), 0, FunctionParams.V);
                        add_gf2(new Pointer(F, NB_WORD_GFqn * (((i * (i + 1)) >>> 1) + 1)), linear_coefs[i], tmp_n);
                    }
                }
                //}
//                }
                nb_root = chooseRootHFE_gf2nx(DR, sk_HFE.F_struct, U);
                if (nb_root == 0)
                {
                    /* fail: retry with an other Rk */
                    continue;
                }
                if (nb_root < 0)
                {
                    /* Error from chooseRootHFE */
//                    if (HFEv != 0)
//                    {
//                        ALIGNED_GFqn_FREE(F);
//                    }
                    return nb_root;
                }
                break;
            }
            while (true);
//            if (HFEv != 0)
//            {
            /* Add the v bits to DR */
//            if (HFEnr != 0)
//            {
            DR.setXor(NB_WORD_GFqn - 1, V.get() << HFEnr);
            for (i = 0; i < (NB_WORD_GFqv - 1); ++i)
            {
                DR.set(NB_WORD_GFqn + i, (V.get(i) >>> (64 - HFEnr)) ^ (V.get(i + 1) << HFEnr));
            }
            if ((NB_WORD_GFqn + NB_WORD_GFqv) == NB_WORD_GF2nv)
            {
                DR.set(NB_WORD_GFqn + i, V.get(i) >>> (64 - HFEnr));
            }
//            }
//            else
//            {
//                for (i = 0; i < NB_WORD_GFqv; ++i)
//                {
//                    DR.set(NB_WORD_GFqn + i, V.get(i));
//                }
//            }
//            }
            /* Finally: compute Sk||Xk = v * S^(-1) */
            vecMatProduct(sm, DR, sk_HFE.S, 0, FunctionParams.NV);
            if (k != NB_ITE)
            {
//            #ifdef KAT_INT
//            fprintBstr_KAT_INT(fp, "Sk||Xk: ", (unsigned char*)sm, NB_BYTES_GFqnv);
//            #endif
                //               if (HFEnv != HFEm)
                /* Store X1 in the signature */
//                {
                index = NB_WORD_GF2nv + (NB_ITE - 1 - k) * NB_WORD_GF2nvm;
                sm.copyFrom(index, sm, NB_WORD_GF2nv - NB_WORD_GF2nvm, NB_WORD_GF2nvm);
                //copy_gf2nvm(sm + index, sm + NB_WORD_GF2nv - NB_WORD_GF2nvm);
                /* To put zeros at the beginning of the first word of X1 */
                if (HFEmr != 0)
                {
                    sm.setAnd(index, ~MASK_GF2m);
                }
                //}

                /* Compute H2 = H(H1) */
//                HASH(( char*)Hi1, ( char*)Hi, SIZE_DIGEST);
                //sha3Digest.reset();
                byte[] Hi_bytes = Hi.toBytes(SIZE_DIGEST);
                //sha3Digest = new SHA3Digest();
                sha3Digest.update(Hi_bytes, 0, Hi_bytes.length);
                byte[] Hi1_bytes = new byte[SIZE_DIGEST];
                sha3Digest.doFinal(Hi1_bytes, 0);
                Hi1.fill(0, Hi1_bytes, 0, SIZE_DIGEST);

                /* Permutation of pointers */
                tmp.changeIndex(Hi1);
                Hi1.changeIndex(Hi);
                Hi.changeIndex(tmp);
            }
        }
//    #if ENABLED_SEED_SK
//            free(sk_HFE.sk_uncomp);
//    #endif
//    #if HFEv
//            ALIGNED_GFqn_FREE(F);
//    #endif
//    #ifdef KAT_INT
//            CLOSE_KAT_INT_FILE;
//    #endif
        if (NB_ITE == 1)
        {
            /* Take the (n+v) first bits */
            byte[] sm64 = sm.toBytes(sm.getLength() << 3);
            System.arraycopy(sm64, 0, sm8, 0, NB_BYTES_GFqnv);
//            for (k = 0; k < NB_BYTES_GFqnv; ++k)
//            {
//                sm8[k] = ((unsigned char*)sm)[k];
//            }
        }
        else
        {
            compress_signHFE(sm8, sm);
        }
        return 0;
    }

    /* Precomputation for one secret-key */
    private int precSignHFE(SecretKeyHFE sk_HFE, Pointer[] linear_coefs, byte[] sk)
    {
        //if HFEv
        Pointer F_HFEv;
        Pointer F_cp;
        Pointer F;
        int i, j;
        final int MLv_GFqn_SIZE = (HFEv + 1) * NB_WORD_GFqn;
        precSignHFESeed(sk_HFE, sk);
//        if (HFEDeg != 1)
//        {
        initListDifferences_gf2nx(sk_HFE.F_struct.L);
        //}
//        if (HFEv != 0)
//        {
        F_HFEv = new Pointer(sk_HFE.F_HFEv);
        final int NB_UINT_HFEPOLY = NB_COEFS_HFEPOLY * NB_WORD_GFqn;
        F = new Pointer(NB_UINT_HFEPOLY);
        //ALIGNED_GFqn_MALLOC(F, UINT *, NB_UINT_HFEPOLY, sizeof(UINT));
        //VERIFY_ALLOC_RET(F);
//            if (HFEDeg > 1)
//            {
        /* X^(2^0) */
        linear_coefs[0] = new Pointer(F_HFEv, MQv_GFqn_SIZE);
        /* X^(2^1) */
        F_HFEv.changeIndex(linear_coefs[0], MLv_GFqn_SIZE);
        F_cp = new Pointer(F, 2 * NB_WORD_GFqn);
        for (i = 0; i < HFEDegI; ++i)
        {
            /* Copy i quadratic terms */
            if (ENABLED_REMOVE_ODD_DEGREE)
            {
                j = (((1 << i) + 1) <= HFE_odd_degree) ? 0 : 1;
            }
            else
            {
                j = 0;
            }
            for (; j < i; ++j)
            {
                /* X^(2^i + 2^j) */
                F_cp.copyFrom(0, F_HFEv, 0, NB_WORD_GFqn);
                F_HFEv.move(NB_WORD_GFqn);
                F_cp.move(NB_WORD_GFqn);
            }
            /* Store the address of X^(2^(i+1)) */
            linear_coefs[i + 1] = new Pointer(F_HFEv);
            /* Linear term is not copied */
            F_HFEv.move(MLv_GFqn_SIZE);
            F_cp.move(NB_WORD_GFqn);
        }
        if (HFEDegJ != 0)
        {
            /* X^(2^HFEDegI + 2^j) */
            //fgemss192 and fgemss256
//            if (ENABLED_REMOVE_ODD_DEGREE)
//            {
            j = (((1 << i) + 1) <= HFE_odd_degree) ? 0 : 1;
//            }
//            else
//            {
//                j = 0;
//            }
            for (; j < HFEDegJ; ++j)
            {
                F_cp.copyFrom(0, F_HFEv, 0, NB_WORD_GFqn);
                F_HFEv.move(NB_WORD_GFqn);
                F_cp.move(NB_WORD_GFqn);
            }
        }
        //}
        sk_HFE.F_struct.poly = new Pointer(F);
//        }
//        else
//        {
//            sk_HFE.F_struct.poly = new Pointer(sk_HFE.F_HFEv);
//        }
        return 0;
    }

    private void precSignHFESeed(SecretKeyHFE sk_HFE, byte[] sk)
    {
//    #if GEN_INV_MATRIX_TRIAL_ERROR
//        expandSeedCxtDeclaration;
//        Mnv_gf2 S_buf;
//        GLnv_gf2 S;
//        GLn_gf2 T;
        //#elif GEN_INVERTIBLE_MATRIX_LU
        Pointer L, U;
        //#endif
        //#if GEN_INVERTIBLE_MATRIX_LU
        sk_HFE.sk_uncomp = new Pointer(NB_UINT_HFEVPOLY + (LTRIANGULAR_NV_SIZE << 1) + (LTRIANGULAR_N_SIZE << 1) + SIZE_VECTOR_t + MATRIXnv_SIZE + MATRIXn_SIZE);
        SHAKEDigest shakeDigest = new SHAKEDigest(ShakeBitStrength);
        shakeDigest.update(sk, 0, SIZE_SEED_SK);
        byte[] sk_uncomp_byte = new byte[(NB_UINT_HFEVPOLY + (LTRIANGULAR_NV_SIZE << 1) + (LTRIANGULAR_N_SIZE << 1) + SIZE_VECTOR_t) << 3];//<< 3
        shakeDigest.doFinal(sk_uncomp_byte, 0, sk_uncomp_byte.length);
        sk_HFE.sk_uncomp.fill(0, sk_uncomp_byte, 0, sk_uncomp_byte.length);
        sk_HFE.S = new Pointer(sk_HFE.sk_uncomp, NB_UINT_HFEVPOLY + (LTRIANGULAR_NV_SIZE << 1) + (LTRIANGULAR_N_SIZE << 1) + SIZE_VECTOR_t);

        //        #if AFFINE_TRANSFORMATION_BY_t
//        sk_HFE -> t = sk_HFE -> sk_uncomp + NB_UINT_HFEVPOLY
//            + (LTRIANGULAR_NV_SIZE << 1)
//            + (LTRIANGULAR_N_SIZE << 1);
//        #endif
//    #elif GEN_INV_MATRIX_TRIAL_ERROR
//        S_buf = MALLOC_MATRIXnv;
//        #if GEN_INVERSE_IN_FIRST
//        ALIGNED_GFqn_MALLOC(sk_HFE -> sk_uncomp, UINT *,
//            SIZE_SK_HFE_UNCOMPRESSED_WORD, sizeof(UINT));
//        #else
//        ALIGNED_GFqn_MALLOC(sk_HFE -> sk_uncomp, UINT *,
//            SIZE_SK_HFE_UNCOMPRESSED_WORD + MATRIXnv_SIZE
//                + MATRIXn_SIZE, sizeof(UINT));
//        #endif
//        expandSeedIUF( & hashInstance, (uint8_t *) sk, SIZE_SEED_SK << 3);
//        expandSeedSqueeze( & hashInstance, (uint8_t *) (sk_HFE -> sk_uncomp),
//        SIZE_SK_HFE_UNCOMPRESSED_WORD << 6);
//
//        S = sk_HFE -> sk_uncomp + ACCESS_MATRIX_S;
//        T = S + MATRIXnv_SIZE;
//
//        #if GEN_INVERSE_IN_FIRST
//        sk_HFE -> S = S;
//        #else
//        sk_HFE -> S = sk_HFE -> sk_uncomp + SIZE_SK_HFE_UNCOMPRESSED_WORD;
//        #endif
//        #if AFFINE_TRANSFORMATION_BY_t
//        sk_HFE -> t = sk_HFE -> sk_uncomp + ACCESS_VECTOR_t;
//        #endif
//    #endif
        sk_HFE.T = new Pointer(sk_HFE.S, MATRIXnv_SIZE);
        /* zero padding for the HFEv polynomial F */
        sk_HFE.F_HFEv = new Pointer(sk_HFE.sk_uncomp);
        cleanMonicHFEv_gf2nx(sk_HFE.F_HFEv);
//    #if GEN_INVERTIBLE_MATRIX_LU
        /* The random bytes are already generated from a seed */
        L = new Pointer(sk_HFE.sk_uncomp, NB_UINT_HFEVPOLY);
        U = new Pointer(L, LTRIANGULAR_NV_SIZE);
        cleanLowerMatrix(L, FunctionParams.NV);
        cleanLowerMatrix(U, FunctionParams.NV);
        //#if GEN_INVERSE_IN_FIRST
        /* Generate S^(-1) = L*U */
        mulMatricesLU_gf2(sk_HFE.S, L, U, FunctionParams.NV);
//        #else
//        /* Generate S the inverse of S^(-1) */
//        invMatrixLUnv_gf2(sk_HFE -> S, L, U);
//        #endif
        /* The random bytes are already generated from a seed */
        L.move(LTRIANGULAR_NV_SIZE << 1);
        U.changeIndex(L, LTRIANGULAR_N_SIZE);

        cleanLowerMatrix(L, FunctionParams.N);
        cleanLowerMatrix(U, FunctionParams.N);

//        #if GEN_INVERSE_IN_FIRST
        /* Generate T^(-1) = L*U */
        mulMatricesLU_gf2(sk_HFE.T, L, U, FunctionParams.N);
//        #else
//        /* Generate T the inverse of T^(-1) */
//        invMatrixLUn_gf2(sk_HFE -> T, L, U);
//        #endif
//
//    #elif GEN_INV_MATRIX_TRIAL_ERROR
//        /* The random bytes are already generated from a seed */
//        cleanMatrix_gf2_nv(S);
//        while (!determinantnv_gf2(S, S_buf))
//        {
//            expandSeedSqueeze( & hashInstance, (uint8_t *) S, MATRIXnv_SIZE << 6);
//            cleanMatrix_gf2_nv(S);
//        }
//
//        #if (!GEN_INVERSE_IN_FIRST)
//    {
//        invMatrixnv_gf2(sk_HFE -> S, S);
//    }
//        #endif
//
//
//        /* The random bytes are already generated from a seed */
//        cleanMatrix_gf2_n(T);
//        while (!determinantn_gf2(T, S_buf))
//        {
//            expandSeedSqueeze( & hashInstance, (uint8_t *) T, MATRIXn_SIZE << 6);
//            cleanMatrix_gf2_n(T);
//        }
//
//        #if (!GEN_INVERSE_IN_FIRST)
//    {
//        invMatrixn_gf2(sk_HFE -> T, T);
//    }
//        #endif
//
//        free(S_buf);
//    #endif
    }

    void cleanMonicHFEv_gf2nx(Pointer F)
    {
        /* zero padding for the last word of each element of GF(2^n) */
        for (int F_idx = NB_WORD_GFqn - 1; F_idx < NB_UINT_HFEVPOLY; F_idx += NB_WORD_GFqn)
        {
            F.setAnd(F_idx, MASK_GF2n);
        }
    }

    private void mulMatricesLU_gf2(Pointer S_orig, Pointer L, Pointer U, FunctionParams functionParams)
    {
        final int nq, nr;//REM=nr
        int iq;
        boolean REM;
        Pointer S = new Pointer(S_orig);
        switch (functionParams)
        {
        case N:
            nq = HFEnq;
            nr = HFEnr;
            REM = true;//HFEnr != 0;
            break;
        case NV:
//            if (HFEv == 0)
//            {
//                return;
//            }
            nq = HFEnvq;
            nr = HFEnvr;
            REM = HFEnvr != 0;
            break;
        default:
            throw new IllegalArgumentException("Invalid parameter for MULMATRICESLU_GF2");
        }
        /* Computation of S = L*U */
        Pointer L_cp = new Pointer(L);
        /* for each row of L (and S) */
        for (iq = 1; iq <= nq; ++iq)
        {
            LOOPIR(S, L_cp, U, NB_BITS_UINT, nq, nr, iq, REM);
        }
        LOOPIR(S, L_cp, U, nr, nq, nr, iq, REM);
    }

    private void LOOPIR(Pointer S, Pointer L_cp, Pointer U, int NB_IT, int nq, int nr, int iq, boolean REM)
    {
        int jq;
        for (int ir = 0; ir < NB_IT; ++ir)
        {
            Pointer U_cp = new Pointer(U);
            /* for each row of U (multiply by the transpose) */
            for (jq = 1; jq <= nq; ++jq)
            {
                LOOPJR(S, L_cp, U_cp, NB_BITS_UINT, iq, jq);
            }
            if (REM)
            {
                LOOPJR(S, L_cp, U_cp, nr, iq, jq);
            }
            L_cp.move(iq);
        }
    }

    private void LOOPJR(Pointer S, Pointer L, Pointer U, int NB_IT, int iq, int jq)
    {
        int mini = Math.min(iq, jq);
        S.set(0, 0);
        int k;
        long tmp;
        for (int jr = 0; jr < NB_IT; ++jr)
        {
            /* Dot product */
            tmp = L.get(0) & U.get(0);
            for (k = 1; k < mini; ++k)
            {
                tmp ^= L.get(k) & U.get(k);
            }
            tmp = XORBITS_UINT(tmp);
            S.setXor(tmp << jr);
            U.move(jq);
        }
        S.moveIncremental();
    }

    private void initListDifferences_gf2nx(Pointer L)
    {
        int i, j, k = 2;
        //Pointer32 L = new Pointer32(L_orig);
        L.set(0);
        final long NB_WORD_GFqn_long = NB_WORD_GFqn;
//        if (HFEDeg != 1)
//        {
        L.set(1, NB_WORD_GFqn_long);
        for (i = 0; i < HFEDegI; ++i)
        {
            if (ENABLED_REMOVE_ODD_DEGREE)
            {
                if (((1 << i) + 1) <= HFE_odd_degree)
                {
                    /* j=0 */
                    L.set(k, NB_WORD_GFqn_long);
                    ++k;
                    /* j=1 to j=i */
                    for (j = 0; j < i; ++j)
                    {
                        L.set(k, NB_WORD_GFqn_long << j);
                        ++k;
                    }
                }
                else
                {
                    /* j=0 */
                    if (i != 0)
                    {
                        L.set(k, NB_WORD_GFqn_long << 1);
                        ++k;
                    }

                    /* j=1 to j=i */
                    for (j = 1; j < i; ++j)
                    {
                        L.set(k, NB_WORD_GFqn_long << j);
                        ++k;
                    }
                }
            }
            else
            {
                /* j=0 */
                L.set(k, NB_WORD_GFqn);
                ++k;
                /* j=1 to j=i */
                for (j = 0; j < i; ++j)
                {
                    L.set(k, NB_WORD_GFqn_long << j);
                    ++k;
                }
            }
        }
        if (HFEDegJ != 0)
        {
            if (ENABLED_REMOVE_ODD_DEGREE)
            {
                if (((1 << i) + 1) <= HFE_odd_degree)
                {
                    /* j=0 */
                    L.set(k, NB_WORD_GFqn_long);
                    ++k;
                    /* j=1 to j=i */
                    for (j = 0; j < (HFEDegJ - 1); ++j)
                    {
                        L.set(k, NB_WORD_GFqn_long << j);
                        ++k;
                    }
                }
                else
                {
                    /* j=0 */
//                    if (HFEDegJ != 1)
//                    {
                    L.set(k, NB_WORD_GFqn_long << 1);
                    ++k;
//                    }
                    /* j=1 to j=i */
                    for (j = 1; j < (HFEDegJ - 1); ++j)
                    {
                        L.set(k, NB_WORD_GFqn_long << j);
                        ++k;
                    }
                }
            }
            else
            {
                /* j=0*/
                L.set(k, NB_WORD_GFqn_long);
                ++k;
                /* j=1 to j=HFEDegJ-1 */
                for (j = 0; j < (HFEDegJ - 1); ++j)
                {
                    L.set(k, NB_WORD_GFqn_long << j);
                    ++k;
                }
            }
        }
        //}
    }

    private void evalMQSv_gf2(Pointer c, Pointer m, Pointer pk_orig)
    {
        long xi;
        Pointer x = new Pointer(HFEv);
        final int NB_EQq = HFEn >>> 6;
        final int NB_EQr = HFEn & 63;
        final int NB_VARq = HFEv >>> 6;
        final int NB_VARr = HFEv & 63;
        final int NB_WORD_EQ = NB_EQr != 0 ? NB_EQq + 1 : NB_EQq;
        Pointer tmp = new Pointer(NB_WORD_EQ);
        Pointer pk = new Pointer(pk_orig);
        int i, j, k;
        /* Compute one time all -((xi>>1)&UINT_1) */
        k = 0;
        for (i = 0; i < NB_VARq; ++i)
        {
            xi = m.get(i);
            for (j = 0; j < NB_BITS_UINT; ++j, ++k)
            {
                x.set(k, -((xi >>> j) & 1));
            }
        }
        if (NB_VARr != 0)
        {
            xi = m.get(i);
            for (j = 0; j < NB_VARr; ++j, ++k)
            {
                x.set(k, -((xi >>> j) & 1));
            }
        }
        /* Constant cst_pk */
        c.copyFrom(pk, NB_WORD_EQ);
//        if (HYBRID_FUNCTIONS)
//        {
//            c[NB_EQq] = pk[NB_EQq];
//        }
        pk.move(NB_WORD_EQ);
        /* for each row of the quadratic matrix of pk, excepted the last block */
        for (i = 0; i < HFEv; ++i)
        {
            /* for each column of the quadratic matrix of pk */
            /* xj=xi */
            tmp.copyFrom(pk, NB_WORD_EQ);
            //COPY_64bits_variables(tmp, pk);
            pk.move(NB_WORD_EQ);
            for (j = i + 1; j < HFEv; ++j)
            {
                xorLoadMask(tmp, pk, x.get(j), NB_WORD_EQ);
                pk.move(NB_WORD_EQ);
            }
            /* Multiply by xi */
            xorLoadMask(c, tmp, x.get(i), NB_WORD_EQ);
        }
    }

    private int chooseRootHFE_gf2nx(Pointer root, SecretKeyHFE.complete_sparse_monic_gf2nx F, Pointer U)
    {
//        if (HFEDeg == 1)
//        {
//            add_gf2(root, F.poly, U, FunctionParams.N);
//            return 1;
//        }
//        else
//        {
        //#if DETERMINIST_ROOT
        Pointer hash = new Pointer(SIZE_DIGEST_UINT);
//        #elif QUARTZ_ROOT
//            UINT * hash;
        int i, l;
        //#endif
        Pointer32 roots = new Pointer32();
        //l = findRootsHFE_gf2nx(roots, F, U);
//            if (HFEDeg == 1)
//            {
//                roots = new Pointer32(NB_WORD_GFqn);
//                add_gf2(roots, F.poly, U, FunctionParams.N);
//                l = 1;
//            }
//            else
//            {
        Pointer tmp_p, poly, poly2;
        //int d2 = HFEDeg;
        poly = new Pointer(((HFEDeg << 1) - 1) * NB_WORD_GFqn);
        poly2 = new Pointer((HFEDeg + 1) * NB_WORD_GFqn);
        /* X^(2^n) - X mod (F-U) */
        l = best_frobeniusMap_HFE_gf2nx(poly, F, U);
        /* Initialize to F */
        convHFEpolynomialSparseToDense_gf2nx(poly2, F);
        /* Initialize to F-U */
        add2_gf2(poly2, U, NB_WORD_GFqn);
        /* GCD(F-U, X^(2^n)-X mod (F-U)) */
        l = gcd_gf2nx(poly2, HFEDeg, poly, l);//d2
        i = buffer;
        if (i != 0)
        {
            tmp_p = poly;
            poly = poly2;
            poly2 = tmp_p;
        }
        if (poly.is0_gf2n(0, NB_WORD_GFqn) == 0)
        {
            /* The gcd is a constant (!=0) */
            /* Irreducible: 0 root */
            /* l=0; */
            l = 0;
        }
        else
        {
            /* poly2 is the gcd */
            /* Here, it becomes monic */
            convMonic_gf2nx(poly2, l);
            roots = new Pointer32(l * NB_WORD_GFqn);
            findRootsSplit_gf2nx(roots, poly2, l);
        }
        //}

        if (l == 0)
        {
            /* Zero root */
            return 0;
        }
        else
        {
            if (l == 1)
            {
                /* One root */
                root.copyFrom(roots, NB_WORD_GFqn);
            }
            else
            {
                /* Several roots */
//                #if QUARTZ_ROOT
//                    hash = (UINT *) malloc(l * SIZE_DIGEST_UINT * sizeof(UINT));
//
//                    /* We hash each root */
//                    for (i = 0; i < l; ++i)
//                    {
//                        HASH((unsigned char*)(hash + i * SIZE_DIGEST_UINT),
//                        (unsigned char*)(roots + i * NB_WORD_GFqn),
//                        NB_BYTES_GFqn);
//                    }
//
//                    /* We search the smallest hash (seen as an integer) */
//                    for (i = 1; i < l; ++i)
//                    {
//                        j = 0;
//                        while ((j < SIZE_DIGEST_UINT) &&
//                            (hash[ind * SIZE_DIGEST_UINT + j] ==
//                                hash[i * SIZE_DIGEST_UINT + j]))
//                        {
//                            ++j;
//                        }
//                        if ((j < SIZE_DIGEST_UINT) &&
//                            (hash[ind * SIZE_DIGEST_UINT + j] >
//                                hash[i * SIZE_DIGEST_UINT + j]))
//                        {
//                            ind = i;
//                        }
//                    }
//
//                    /* We choose the corresponding root */
//                    copy_gf2n(root, roots + ind * NB_WORD_GFqn);
//
//                    free(hash);
//                #else
                /* Sort the roots */
                sort_gf2n(roots, l);
//                    #if FIRST_ROOT
//                    /* Choose the first root */
//                    copy_gf2n(root, roots);
//                    #elif DETERMINIST_ROOT
                /* Choose a root with a determinist hash */
                SHA3Digest sha3Digest = new SHA3Digest(Sha3BitStrength);
                byte[] U_bytes = U.toBytes(NB_BYTES_GFqn);
                byte[] hash_bytes = new byte[Sha3BitStrength >> 3];
                sha3Digest.update(U_bytes, 0, U_bytes.length);
                sha3Digest.doFinal(hash_bytes, 0);
                hash.fill(0, hash_bytes, 0, hash_bytes.length);
                long tmp = Long.remainderUnsigned(hash.get(), l);
                root.copyFrom(0, roots, (int)tmp * NB_WORD_GFqn, NB_WORD_GFqn);
//                    #endif
//                #endif
            }
            //free(roots);
            return l;
        }
        //}
    }

    private int gcd_gf2nx(Pointer A, int da, Pointer B, int db)
    {
        Pointer inv = new Pointer(NB_WORD_GFqn);
        Pointer tmp;
        int i;
        /* *b = 0: B is the last remainder
         *b = 1: A is the last remainder */
        buffer = 0;
        while (db != 0)
        {
            /* Computation of A = A mod B, of degree da */
            /* Minimizes the number of multiplications by an inverse */
            /* 2db > da */
            if ((db << 1) > da)
            {
                /* At most da-db+1 multiplications by an inverse */
                da = div_r_gf2nx(A, da, B, db);
            }
            else
            {
                /* B becomes monic: db multiplications by an inverse */
                inv_gf2n(inv, B, db * NB_WORD_GFqn);
                B.set1_gf2n(db * NB_WORD_GFqn, NB_WORD_GFqn);
                for (i = db - 1; i != -1; --i)
                {
                    mul_gf2n(new Pointer(B, i * NB_WORD_GFqn), new Pointer(B, i * NB_WORD_GFqn), inv);
                }
                da = div_r_monic_gf2nx(A, da, B, db);
            }

            /* Swaps A and B */
            tmp = A;
            A = B;
            B = tmp;
            /* Swaps da and db */
            int tmp_word = da;
            da = db;
            db = tmp_word;
            /* 0 becomes 1 and 1 becomes 0 */
            buffer = 1 - buffer;
        }
        return da;
    }

    private int best_frobeniusMap_HFE_gf2nx(Pointer Xqn, SecretKeyHFE.complete_sparse_monic_gf2nx F, Pointer U)
    {
        Pointer cst = new Pointer(NB_WORD_GFqn);
        //if (HFEDegI==HFEDegJ)
//        Pointer F_cp;
//        Pointer Xqn_cp;
        //#endif
        //#if CONSTANT_TIME
        long b, mask;
        //#endif
        int d, i;

        /* Constant term of F-U */
        add_gf2(cst, F.poly, U);

    /* For i=HFEDegI, we have X^(2^i) mod (F-U) = X^(2^i).
       The first term of degree >= HFEDeg is X^(2^(HFEDegI+1)):
       2^(HFEDegI+1) >= HFEDeg but 2^HFEDegI < HFEDeg.
       So, we begin at the step i=HFEDegI+1 */
//        if (HFEDegI == HFEDegJ)
//        {
//            throw new IllegalArgumentException("Have not implemented for this branch!");
        /* Compute X^(2^(HFEDegI+2)) mod (F-U) */
        /* We have X^D = X^(2^HFEDegI + 2^HFEDegJ) = X^(2^(HFEDegI+1)).
           So, X^(2^(HFEDegI+1)) mod (F-U) = F-U - X^D.
           Then, X^(2^(HFEDegI+2)) = (F-U - X^D)^2 mod (F-U) */
        /* Step 1: compute (F-U - X^D)^2 */
//            F_cp = new Pointer(F.poly);
//            Xqn_cp = new Pointer(Xqn);
//
//            sqr_gf2n(Xqn_cp, cst);
//            for (i = 1; i < NB_COEFS_HFEPOLY; ++i)
//            {
//                F_cp.move( NB_WORD_GFqn);
//                /* Multiplication by 2 to have the coefficient of the square */
//                Xqn_cp += (F.L[i]) << 1;
//                sqr_gf2n(Xqn_cp, F_cp);
//            }
//            /* Degree of (F-U - X^D)^2 */
//            if (HFEDeg == 2)
//            {
//                d = 2;
//            }
//            else
//            {
//                d = HFEDeg + (1 U << HFEDegI);
//            }
        /* Step 2: reduction of (F-U - X^D)^2 modulo (F-U) */
//        #if CONSTANT_TIME
//            divsqr_r_HFE_cstdeg_gf2nx(Xqn, d, F, cst);
//        #else
//            d = div_r_HFE_gf2nx(Xqn, d, F, cst);
//        #endif
//
//            for (i = HFEDegI + 2; i < HFEn; ++i)
//        }
//        else
//        {
        /* Compute X^(2^(HFEDegI+1)) mod (F-U) */
        /* Step 1: compute X^(2^(HFEDegI+1)) */
        d = 2 << HFEDegI;
        /* Xqn is initialized to 0 with calloc, so the multiprecision word is initialized to 1 just by setting the first word */
        Xqn.set(d * NB_WORD_GFqn, 1);
        /* Step 2: reduction of X^(2^(HFEDegI+1)) modulo (F-U) */
//        #if CONSTANT_TIME
        divsqr_r_HFE_cstdeg_gf2nx(Xqn, d, F, cst);
//        #else
//            d = div_r_HFE_gf2nx(Xqn, d, F, cst);
//        #endif
        i = HFEDegI + 1;
        //}
        for (; i < HFEn; ++i)
        {
            //#if CONSTANT_TIME
            /* Step 1: (X^(2^i) mod (F-U))^2 = X^(2^(i+1)) */
            sqr_HFE_gf2nx(Xqn);
            /* Step 2: X^(2^(i+1)) mod (F-U) */
            divsqr_r_HFE_cstdeg_gf2nx(Xqn, (HFEDeg - 1) << 1, F, cst);
//        #else
//            /* Step 1: (X^(2^i) mod (F-U))^2 = X^(2^(i+1)) */
//            sqr_gf2nx(Xqn, d);
//            /* Step 2: X^(2^(i+1)) mod (F-U) */
//            d = div_r_HFE_gf2nx(Xqn, d << 1U, F, cst);
//        #endif
        }
        /* (X^(2^n) mod (F-U)) - X */
        Xqn.setXor(NB_WORD_GFqn, 1);
        /* Search the degree of X^(2^n) - X mod (F-U) */
        //#if CONSTANT_TIME
        d = 0;
        mask = 0;
        for (i = HFEDeg - 1; i > 0; --i)
        {
            b = isNot0_gf2n(Xqn, i * NB_WORD_GFqn, NB_WORD_GFqn);
            mask |= b;
            /* We add 1 to d as soon as we exceed all left zero coefficients */
            d += mask;
        }
//    #else
//        if (d == 1)
//        {
//            if (is0_gf2n(Xqn + NB_WORD_GFqn))
//            {
//                d = 0;
//            }
//        }
//    #endif
        return d;
    }

    private void divsqr_r_HFE_cstdeg_gf2nx(Pointer poly, int dp, SecretKeyHFE.complete_sparse_monic_gf2nx F, Pointer cst)
    {
        Pointer mul_coef = new Pointer(NB_WORD_GFqn);
        Pointer leading_coef, res;
        int i;
        Pointer L = new Pointer(F.L);
        for (; dp >= HFEDeg; --dp)
        {
            leading_coef = new Pointer(poly, dp * NB_WORD_GFqn);
            res = new Pointer(leading_coef, -HFEDeg * NB_WORD_GFqn);
            /* i=0: Constant of F-U */
            mul_gf2n(mul_coef, leading_coef, cst);
            add2_gf2(res, mul_coef, NB_WORD_GFqn);
            for (i = 1; i < NB_COEFS_HFEPOLY; ++i)
            {
                mul_gf2n(mul_coef, leading_coef, new Pointer(F.poly, i * NB_WORD_GFqn));
                res.move((int)L.get(i));
                add2_gf2(res, mul_coef, NB_WORD_GFqn);
            }
        }
    }

    private void sqr_HFE_gf2nx(Pointer poly)
    {
        int i = NB_WORD_GFqn * (HFEDeg - 1);
        /* Pointer on the last coefficient of poly */
        poly.move(i);
        /* Pointer on the last coefficient of the square of poly */
        Pointer poly_2i = new Pointer(poly, i);
        /* Square of each coefficient, a_i X^i becomes a_i^2 X^(2i).
       Order: X^d X^(d-1) X^(d-2) ... X^(d-i) ... X^2 X^1 for d=HFEDeg-1 */
        for (i = 0; i < (HFEDeg - 1); ++i)
        {
            sqr_gf2n(poly_2i, poly);
            poly.move(-NB_WORD_GFqn);
            poly_2i.move(-NB_WORD_GFqn);
            /* The coefficient of X^(2(d-i)-1) is set to 0 (odd exponent) */
            poly_2i.setRangeClear(0, NB_WORD_GFqn);
            poly_2i.move(-NB_WORD_GFqn);
        }
        /* Square of the coefficient of X^0 */
        sqr_gf2n(poly, poly);
    }

    private long isNot0_gf2n(Pointer a, int shift, int size)
    {
        long r;
        int i;
        r = a.get(shift);
        for (i = 1; i < size; ++i)
        {
            r |= a.get(shift + i);
        }
        for (i = size; i > 0; i >>>= 1)
        {
            r |= r >>> i;
        }
        r &= 1;
        return r;
    }

    private void convHFEpolynomialSparseToDense_gf2nx(Pointer F_dense, SecretKeyHFE.complete_sparse_monic_gf2nx F)
    {
        Pointer F_cp = new Pointer(F.poly);
        Pointer F_dense_cp = new Pointer(F_dense);
        /* i=0: constant of F */
        F_dense.copyFrom(0, F_cp, 0, NB_WORD_GFqn);
        for (int i = 1; i < NB_COEFS_HFEPOLY; ++i)
        {
            F_dense_cp.move((int)F.L.get(i));
            F_dense_cp.copyFrom(0, F_cp, i * NB_WORD_GFqn, NB_WORD_GFqn);
        }
        /* Leading term: 1 */
        F_dense.set(HFEDeg * NB_WORD_GFqn, 1);
    }

    int div_r_gf2nx(Pointer A, int da, Pointer B, int db)
    {
        Pointer mul_coef = new Pointer(NB_WORD_GFqn);
        Pointer leading_coef = new Pointer(NB_WORD_GFqn);
        Pointer inv = new Pointer(NB_WORD_GFqn);
        Pointer res = new Pointer(A);
        int i;
        /* Compute the inverse of the leading term of B */
        inv_gf2n(inv, B, db * NB_WORD_GFqn);
        /* modular reduction */
        while (da >= db)
        {
            /* Search the current degree of A */
            while (A.is0_gf2n(da * NB_WORD_GFqn, NB_WORD_GFqn) != 0 && (da >= db))
            {
                --da;
            }
            if (da < db)
            {
                /* The computation of the remainder is finished */
                break;
            }
            res.changeIndex((da - db) * NB_WORD_GFqn);
            mul_gf2n(leading_coef, new Pointer(A, da * NB_WORD_GFqn), inv);
            /* i=0: Constant of B */
            mul_gf2n(mul_coef, leading_coef, B);
            add2_gf2(res, mul_coef, NB_WORD_GFqn);
            for (i = 1; i < db; ++i)
            {
                mul_gf2n(mul_coef, leading_coef, new Pointer(B, i * NB_WORD_GFqn));
                res.move(NB_WORD_GFqn);
                add2_gf2(res, mul_coef, NB_WORD_GFqn);
            }
            /* The leading term becomes 0 */
            /* useless because every coefficients >= db will be never used */
            /* set0_gf2n(leading_coef); */
            --da;
        }

        /* Here, da=db-1 */
        while (A.is0_gf2n(da * NB_WORD_GFqn, NB_WORD_GFqn) != 0 && da != 0)
        {
            --da;
        }

        /* Degree of the remainder */
        return da;
    }

    private void div_q_monic_gf2nx(Pointer A, int da, Pointer B, int db)
    {
        Pointer mul_coef = new Pointer(NB_WORD_GFqn);
        Pointer leading_coef, res;
        int i;
        /* modular reduction */
        while (da >= db)
        {
            /* Search the current degree of A */
            while (A.is0_gf2n(da * NB_WORD_GFqn, NB_WORD_GFqn) != 0 && da >= db)
            {
                --da;
            }
            if (da < db)
            {
                /* The computation of the remainder is finished */
                break;
            }
            leading_coef = new Pointer(A, da * NB_WORD_GFqn);
            i = (db << 1) - da;
            i = Math.max(0, i);
            res = new Pointer(A, (da - db + i) * NB_WORD_GFqn);
            for (; i < db; ++i)
            {
                mul_gf2n(mul_coef, leading_coef, new Pointer(B, i * NB_WORD_GFqn));
                add2_gf2(res, mul_coef, NB_WORD_GFqn);
                res.move(NB_WORD_GFqn);
            }
            /* The leading term of A is a term of the quotient */
            --da;
        }
        if (da == -1)
        {
            ++da;
        }
        /* Here, da=db-1 */
        while (da != 0 && A.is0_gf2n(da * NB_WORD_GFqn, NB_WORD_GFqn) != 0)
        {
            --da;
        }
        /* Degree of the remainder */
        //return da;
    }

    private int div_r_monic_gf2nx(Pointer A, int da, Pointer B, int db)
    {
        Pointer mul_coef = new Pointer(NB_WORD_GFqn);
        Pointer leading_coef, res;
        int i;

        /* modular reduction */
        while (da >= db)
        {
            /* Search the current degree of A */
            while (A.is0_gf2n(da * NB_WORD_GFqn, NB_WORD_GFqn) != 0 && (da >= db))
            {
                --da;
            }

            if (da < db)
            {
                /* The computation of the remainder is finished */
                break;
            }

            leading_coef = new Pointer(A, da * NB_WORD_GFqn);
            res = new Pointer(leading_coef, -db * NB_WORD_GFqn);
            /* i=0: Constant of B */
            mul_gf2n(mul_coef, leading_coef, B);
            add2_gf2(res, mul_coef, NB_WORD_GFqn);
            for (i = 1; i < db; ++i)
            {
                mul_gf2n(mul_coef, leading_coef, new Pointer(B, i * NB_WORD_GFqn));
                res.move(NB_WORD_GFqn);
                add2_gf2(res, mul_coef, NB_WORD_GFqn);
            }
            /* The leading term of A is a term of the quotient */
            --da;
        }

        if (da == (-1))
        {
            ++da;
        }

        /* Here, da=db-1 */
        while (da != 0 && A.is0_gf2n(da * NB_WORD_GFqn, NB_WORD_GFqn) != 0)
        {
            --da;
        }
        /* Degree of the remainder */
        return da;
    }

    private void inv_gf2n(Pointer res, Pointer A, int AOff)
    {
        int A_orig = A.getIndex();
        A.move(AOff);
//        if (HFEn == 1)
//        {
//            res.set(A.get());
//        }
//        else
//        {
        Pointer multi_sqr = new Pointer(NB_WORD_GFqn);
        int pos, nb_sqr, i, j;
        /* Search the position of the MSB of n-1 */
        pos = 31;
        while (((HFEn - 1) >>> pos) == 0)
        {
            --pos;
        }
        /* i=pos */
        res.copyFrom(A, NB_WORD_GFqn);
        for (i = pos - 1; i != (-1); --i)
        {
            nb_sqr = (HFEn - 1) >>> (i + 1);
            /* j=0 */
            sqr_gf2n(multi_sqr, res);
            for (j = 1; j < nb_sqr; ++j)
            {
                sqr_gf2n(multi_sqr, multi_sqr);
            }
            mul_gf2n(res, res, multi_sqr);
            if ((((HFEn - 1) >>> i) & 1) != 0)
            {
                sqr_gf2n(multi_sqr, res);

                mul_gf2n(res, A, multi_sqr);
            }
        }
        sqr_gf2n(res, res);
        //}
        A.changeIndex(A_orig);
    }

    private void convMonic_gf2nx(Pointer F_orig, int d)
    {
        Pointer inv = new Pointer(NB_WORD_GFqn);
        Pointer F = new Pointer(F_orig);
        F.move(d * NB_WORD_GFqn);
        /* At this step, F is the pointer on the term X^d of F */
        inv_gf2n(inv, F, 0);
        F.set1_gf2n(0, NB_WORD_GFqn);
        for (int i = d - 1; i != -1; --i)
        {
            F.move(-NB_WORD_GFqn);
            /* At this step, F is the pointer on the term X^i of F */
            mul_gf2n(F, F, inv);
        }
    }

    private void findRootsSplit_gf2nx(Pointer roots, Pointer f, int deg)
    {
        Pointer poly_trace;
        Pointer f_cp;
        Pointer tmp_p = new Pointer();
        Pointer poly_frob;
        Pointer inv = new Pointer(NB_WORD_GFqn);
        int b, i, l, d;
        if (deg == 1)
        {
            /* Extract the unique root which is the constant of f */
            roots.copyFrom(f, NB_WORD_GFqn);
            return;
        }
        if ((HFEn & 1) != 0)
        {
            if (deg == 2)
            {
                findRootsSplit2_HT_gf2nx(roots, f);
                return;
            }
        }
        poly_frob = new Pointer(((deg << 1) - 1) * NB_WORD_GFqn);
        /* poly_trace is modulo f, this degree is strictly less than deg */
        poly_trace = new Pointer(deg * NB_WORD_GFqn);
        /* f_cp a copy of f */
        f_cp = new Pointer((deg + 1) * NB_WORD_GFqn);
        do
        {
            /* Set poly_frob to zero */
            poly_frob.setRangeClear(0, ((deg << 1) - 1) * NB_WORD_GFqn);
            /* Set poly_trace to zero */
            poly_trace.setRangeClear(0, deg * NB_WORD_GFqn);

            /* Initialization to rX */
            /* Probability 2^(-n) to find 0 with a correct RNG */
            do
            {
                //rand_gf2n(new Pointer(poly_trace, NB_WORD_GFqn));
                poly_trace.fillRandom(NB_WORD_GFqn, random, NB_BYTES_GFqn);
//                if (HFEnr != 0)
//                {
                /* Clean the last word (included the zero padding) */
                poly_trace.setAnd((NB_WORD_GFqn << 1) - 1, MASK_GF2n);
                //}
            }
            while (poly_trace.is0_gf2n(NB_WORD_GFqn, NB_WORD_GFqn) != 0);

            /* copy of f because the gcd modifies f */
            f_cp.copyFrom(f, (deg + 1) * NB_WORD_GFqn);
            //copy_gf2nx(f_cp, f, deg + 1, l);

            traceMap_gf2nx(poly_trace, poly_frob, f_cp, deg);
            /* Degree of poly_trace */
            d = deg - 1;
            while (poly_trace.is0_gf2n(d * NB_WORD_GFqn, NB_WORD_GFqn) != 0 && d != 0)
            {
                --d;
            }
            l = gcd_gf2nx(f_cp, deg, poly_trace, d);
            b = buffer;
        }
        while ((l == 0) || (l == deg));
//        free(poly_frob);

        if (b != 0)
        {
            tmp_p.changeIndex(poly_trace);
            poly_trace.changeIndex(f_cp);
            f_cp.changeIndex(tmp_p);
        }
        /* Here, f_cp is a non-trivial divisor of degree l */
        //free(poly_trace);

        /* f_cp is the gcd */
        /* Here, it becomes monic */
        inv_gf2n(inv, f_cp, l * NB_WORD_GFqn);
        f_cp.set1_gf2n(l * NB_WORD_GFqn, NB_WORD_GFqn);

        for (i = l - 1; i != -1; --i)
        {
            mul_gf2n(new Pointer(f_cp, i * NB_WORD_GFqn), new Pointer(f_cp, i * NB_WORD_GFqn), inv);
        }

        /* f = f_cp * Q */
        /* This function destroyes f */
        div_q_monic_gf2nx(f, deg, f_cp, l);
        /* Necessarily, the polynomial f is null here */

        /* f_cp is monic */
        /* We can apply findRootsSplit_gf2nx recursively */
        findRootsSplit_gf2nx(roots, f_cp, l);
        //free(f_cp);

        /* f is monic and f_cp is monic so Q is monic */
        /* We can apply findRootsSplit_gf2nx recursively */
        findRootsSplit_gf2nx(new Pointer(roots, l * NB_WORD_GFqn), new Pointer(f, l * NB_WORD_GFqn), deg - l);
    }

    void findRootsSplit2_HT_gf2nx(Pointer roots_orig, Pointer f_orig)
    {
        Pointer c = new Pointer(NB_WORD_GFqn);
        Pointer alpha = new Pointer(NB_WORD_GFqn);
        Pointer f = new Pointer(f_orig);
        //TODO: Since roots_orig is a Pointer32, the set and get method may have some bugs
        Pointer roots = new Pointer(roots_orig);
        sqr_gf2n(c, new Pointer(f, NB_WORD_GFqn));
        inv_gf2n(roots, c, 0);
        mul_gf2n(c, f, roots);
        findRootsSplit_x2_x_c_HT_gf2nx(alpha, c);
        f.move(NB_WORD_GFqn);
        mul_gf2n(roots, alpha, f);
        add_gf2(new Pointer(roots, NB_WORD_GFqn), roots, f);
    }

    void findRootsSplit_x2_x_c_HT_gf2nx(Pointer root, Pointer c)
    {
        Pointer alpha = new Pointer(NB_WORD_GFqn);
        final int e = (HFEn + 1) >> 1;
        int i, j, e2, pos;
        /* Search the position of the MSB of n-1 */
        pos = 31;
        while ((e >> pos) == 0)
        {
            --pos;
        }
        /* i=pos */
        root.copyFrom(c, NB_WORD_GFqn);
        e2 = 1;
        for (i = pos - 1; i != -1; --i)
        {
            e2 <<= 1;
            /* j=0 */
            sqr_gf2n(alpha, root);
            for (j = 1; j < e2; ++j)
            {
                sqr_gf2n(alpha, alpha);
            }
            root.setXorRange(0, alpha, 0, NB_WORD_GFqn);

            e2 = e >> i;
            if ((e2 & 1) != 0)
            {
                sqr_gf2n(alpha, root);
                sqr_gf2n(root, alpha);
                root.setXorRange(0, c, 0, NB_WORD_GFqn);
            }
        }
    }

    private void traceMap_gf2nx(Pointer poly_trace, Pointer poly_frob, Pointer f, int deg)
    {
        /* d is the degree of poly_frob */
        //int d;
        int i = 1, min;
        /* (2^i) < deg does not require modular reduction by f */
//        if (HFEn < 33)
//        {
//            min = (deg < (1 << HFEn)) ? deg : HFEn;
//        }
//        else
//        {
        min = deg;
        //}
        while ((1 << i) < min)
        {
            /* poly_trace += ((rX)^(2^i)) mod f.  Here, ((rX)^(2^i)) mod f == (rX)^(2^i) since (2^i) < deg */
            sqr_gf2n(new Pointer(poly_trace, (NB_WORD_GFqn << i)), new Pointer(poly_trace, NB_WORD_GFqn << (i - 1)));
            ++i;
        }

        /* Here, (rX)^(2^i) is the first time where we need modular reduction */
        if (i < HFEn)
        {
            /* poly_frob = (rX)^(2^i) = ((rX)^(2^(i-1)))^2 */
            sqr_gf2n(new Pointer(poly_frob, NB_WORD_GFqn << i), new Pointer(poly_trace, NB_WORD_GFqn << (i - 1)));
//        #if CONSTANT_TIME
            /* poly_frob = ((rX)^(2^i)) mod f */
            div_r_monic_cst_gf2nx(poly_frob, 1 << i, f, deg);
            /* poly_trace += ((rX)^(2^i)) mod f */
            add2_gf2(poly_trace, poly_frob, deg * NB_WORD_GFqn);
//        #else
//            /* poly_frob = ((rX)^(2^i)) mod f */
//            d = div_r_monic_gf2nx(poly_frob, 1U << i, f, deg);
//            /* poly_trace += ((rX)^(2^i)) mod f */
//            add2_gf2nx(poly_trace, poly_frob, d + 1, j);
//        #endif
            ++i;
            for (; i < HFEn; ++i)
            {
                //#if CONSTANT_TIME
                /* poly_frob = (rX)^(2^i) = ((rX)^(2^(i-1)) mod f)^2 */
                sqr_gf2nx(poly_frob, deg - 1);
                /* poly_frob = ((rX)^(2^i)) mod f */
                div_r_monic_cst_gf2nx(poly_frob, (deg - 1) << 1, f, deg);
                /* poly_trace += ((rX)^(2^i)) mod f */
                add2_gf2(poly_trace, poly_frob, (deg) * NB_WORD_GFqn);
//            #else
//                /* poly_frob = (rX)^(2^i) = ((rX)^(2^(i-1)) mod f)^2 */
//                sqr_gf2nx(poly_frob, d);
//                /* poly_frob = ((rX)^(2^i)) mod f */
//                d = div_r_monic_gf2nx(poly_frob, d << 1U, f, deg);
//                /* poly_trace += ((rX)^(2^i)) mod f */
//                add2_gf2nx(poly_trace, poly_frob, d + 1, j);
//            #endif
            }
        }
    }

    private void div_r_monic_cst_gf2nx(Pointer A_orig, int da, Pointer B, int db)
    {
        Pointer mul_coef = new Pointer(NB_WORD_GFqn);
        Pointer res;
        int i;
        Pointer A = new Pointer(A_orig);
        /* Pointer on the current leading term of A */
        A.move(da * NB_WORD_GFqn);
        for (; da >= db; --da)
        {
            res = new Pointer(A, -db * NB_WORD_GFqn);
            for (i = 0; i < db; ++i)
            {
                mul_gf2n(mul_coef, A, new Pointer(B, i * NB_WORD_GFqn));
                add2_gf2(res, mul_coef, NB_WORD_GFqn);
                res.move(NB_WORD_GFqn);
            }
            /* useless because every coefficients >= db will be never used */
            /* set0_gf2n(leading_coef); */
            A.move(-NB_WORD_GFqn);
        }
    }

    private void sqr_gf2nx(Pointer poly_orig, int d)
    {
        int i = NB_WORD_GFqn * d;
        /* Pointer on the last coefficient of poly */
        Pointer poly = new Pointer(poly_orig);
        poly.move(i);
        /* A pointer on X^(2*(d-i)) */
        /* Pointer on the last coefficient of the square of poly */
        Pointer poly_2i = new Pointer(poly, i);

    /* Square of each coefficient, a_i X^i becomes a_i^2 X^(2i).
       Order: X^d X^(d-1) X^(d-2) ... X^(d-i) ... X^2 X^1 */
        for (i = 0; i < d; ++i)
        {
            sqr_gf2n(poly_2i, poly);
            poly.move(-NB_WORD_GFqn);
            poly_2i.move(-NB_WORD_GFqn);
            /* The coefficient of X^(2(d-i)-1) is set to 0 (odd exponent) */
            poly_2i.setRangeClear(0, NB_WORD_GFqn);
            poly_2i.move(-NB_WORD_GFqn);
        }
        /* Square of the coefficient of X^0 */
        sqr_gf2n(poly, poly);
    }

    private void sort_gf2n(Pointer tab_orig, int l)
    {
        Pointer tab = new Pointer(tab_orig);
        Pointer sum = new Pointer(NB_WORD_GFqn);
        Pointer prod = new Pointer(NB_WORD_GFqn);
        Pointer tab_lim, tab_j;
        long mask;
        tab_lim = new Pointer(tab, NB_WORD_GFqn * (l - 1));
        for (; tab.getIndex() < tab_lim.getIndex(); tab.move(NB_WORD_GFqn))
        {
            for (tab_j = new Pointer(tab, NB_WORD_GFqn); tab_j.getIndex() <= tab_lim.getIndex(); tab_j.move(NB_WORD_GFqn))
            {
                mask = -cmp_lt_gf2n(tab_j, tab, NB_WORD_GFqn);//f_CMP_LT(a,b,NB_WORD_GFqn)
                add_gf2(sum, tab, tab_j);
                prod.setRangeClear(0, NB_WORD_GFqn);
                xorLoadMask(prod, sum, mask, NB_WORD_GFqn);
                add2_gf2(tab_j, prod, NB_WORD_GFqn);
                add2_gf2(tab, prod, NB_WORD_GFqn);
            }
        }
    }


    private int cmp_lt_gf2n(Pointer a_orig, Pointer b_orig, int size)
    {
        Pointer a = new Pointer(a_orig);
        Pointer b = new Pointer(b_orig);
        long d, bo, mask;
        int i;
        /* Compute d the larger index such as a[d]!=b[d], in constant-time */
        d = 0;
        mask = 0;
        for (i = size - 1; i > 0; --i)
        {
            bo = a.get(i) ^ b.get(i);
            bo = ORBITS_UINT(bo);
            mask |= bo;
            d += mask;
        }
        /* Return a[d]<b[d] in constant-time */
        mask = 0;
        for (i = 0; i < size; ++i)
        {
            bo = i ^ d;
            bo = NORBITS_UINT(bo);
            mask |= (-bo) & CMP_LT_UINT(a.get(), b.get());
            a.moveIncremental();
            b.moveIncremental();
        }
        return (int)mask;
    }

    private long CMP_LT_UINT(long a, long b)
    {
        return (((((a) >>> 63) ^ ((b) >>> 63)) & ((((a) >>> 63) - ((b) >>> 63)) >>> 63))
            ^ ((((a) >>> 63) ^ ((b) >>> 63) ^ 1L) & ((((a) & (0x7FFFFFFFFFFFFFFFL))
            - ((b) & (0x7FFFFFFFFFFFFFFFL))) >>> 63)));
    }

    public void compress_signHFE(byte[] sm8, Pointer sm)
    {
        byte[] sm64 = sm.toBytes(sm.getLength() << 3);
        //Pointer sm64 = new Pointer(sm);
        int k2, sm64_cp = 0;
        /* Take the (n+v) first bits */
        System.arraycopy(sm64, 0, sm8, 0, NB_BYTES_GFqnv);
        /* Take the (Delta+v)*(nb_ite-1) bits */
        if (NB_ITE > 1)//(NB_ITE > 1) || HFEDELTA + HFEv == 0
        {
            int k1, nb_bits, nb_rem2, nb_rem_m, val_n;
            //if (HFEmr8)
            int nb_rem;
            //#endif
            /* HFEnv bits are already stored in sm8 */
            nb_bits = HFEnv;
            sm64_cp += (NB_WORD_GF2nv << 3) + (HFEmq8 & 7);
            for (k1 = 1; k1 < NB_ITE; ++k1)
            {
                /* Number of bits to complete the byte of sm8, in [0,7] */
                val_n = Math.min((HFEDELTA + HFEv), ((8 - (nb_bits & 7)) & 7));
                /* First byte of sm8 */
                if ((nb_bits & 7) != 0)
                {
                    if (HFEmr8 != 0)
                    {
                        sm8[nb_bits >>> 3] ^= ((sm64[sm64_cp] & 0xFF) >>> HFEmr8) << (nb_bits & 7);
                        /* Number of bits to complete the first byte of sm8 */
                        nb_rem = ((val_n - VAL_BITS_M));
                        if (nb_rem >= 0)
                        {
                            /* We take the next byte since we used VAL_BITS_M bits */
                            sm64_cp++;
                        }
                        if (nb_rem > 0)
                        {
                            nb_bits += VAL_BITS_M;
                            sm8[nb_bits >>> 3] ^= (sm64[sm64_cp] & 0xFF) << (nb_bits & 7);
                            nb_bits += nb_rem;
                        }
                        else
                        {
                            nb_bits += val_n;
                        }
                    }
                    else
                    {
                        /* We can take 8 bits, and we want at most 7 bits. */
                        sm8[nb_bits >>> 3] ^= (sm64[sm64_cp] & 0xFF) << (nb_bits & 7);
                        nb_bits += val_n;
                    }
                }
                /* Other bytes of sm8 */
                nb_rem2 = (HFEDELTA + HFEv) - val_n;
                /*nb_rem2 can be zero only in this case */
//                if (HFEDELTA + HFEv >= 8 || nb_rem2 != 0)
//                {
                /* Number of bits used of sm64, mod 8 */
                nb_rem_m = (HFEm + val_n) & 7;
                /* Other bytes */
                if (nb_rem_m != 0)
                {
                    /* -1 to take the ceil of /8, -1 */
                    for (k2 = 0; k2 < ((nb_rem2 - 1) >>> 3); ++k2)
                    {
                        sm8[nb_bits >>> 3] = (byte)(((sm64[sm64_cp] & 0xFF) >>> nb_rem_m) ^ ((sm64[sm64_cp + 1] & 0xFF) << (8 - nb_rem_m)));
                        nb_bits += 8;
                        sm64_cp++;
                    }
                    /* The last byte of sm8, between 1 and 8 bits to put */
                    sm8[nb_bits >>> 3] = (byte)((sm64[sm64_cp] & 0xFF) >>> nb_rem_m);
                    ++sm64_cp;
                    /* nb_rem2 between 1 and 8 bits */
                    nb_rem2 = ((nb_rem2 + 7) & 7) + 1;
                    if (nb_rem2 > (8 - nb_rem_m))
                    {
                        sm8[nb_bits >>> 3] ^= (byte)((sm64[sm64_cp] & 0xFF) << (8 - nb_rem_m));
                        ++sm64_cp;
                    }
                    nb_bits += nb_rem2;
                }
                else
                {
                    /* We are at the beginning of the bytes of sm8 and sm64 */
                    /* +7 to take the ceil of /8 */
                    for (k2 = 0; k2 < ((nb_rem2 + 7) >>> 3); ++k2)
                    {
                        sm8[nb_bits >>> 3] = sm64[sm64_cp];
                        nb_bits += 8;
                        ++sm64_cp;
                    }
                    /* The last byte has AT MOST 8 bits. */
                    nb_bits -= (8 - (nb_rem2 & 7)) & 7;
                }
//                }
//                else if ((HFEDELTA + HFEv) < 8)
//                {
//                    ++sm64_cp;
//                }
                /* We complete the word. Then we search the first byte. */
                sm64_cp += ((8 - (NB_BYTES_GFqnv & 7)) & 7) + (HFEmq8 & 7);
            }
        }

    }

    void convMQS_one_to_last_mr8_equations_gf2(byte[] pk_U, PointerUnion pk_cp)
    {
        int ir, jq, jr;
        int pk_U_cp = 0;
        /* To have equivalence between *pk and pk[iq] */
        pk_cp.indexReset();
        pk_cp.moveNextBytes(HFEmq8);
        PointerUnion pk_cp2 = new PointerUnion(pk_cp);
        final int HFENq8 = NB_MONOMIAL_PK >>> 3;
        /* For each equation of result */
        for (ir = 0; ir < HFEmr8; ++ir)
        {
            /* Loop on every monomials */
            pk_cp2.changeIndex(pk_cp);
            for (jq = 0; jq < HFENq8; ++jq)
            {
                /* jr=0 */
                pk_U[pk_U_cp] = (byte)((pk_cp2.getByte() >>> ir) & 1);
                //pk_U[pk_U_cp] = pk_cp2.getByte();
                pk_cp2.moveNextBytes(NB_BYTES_GFqm);
                for (jr = 1; jr < 8; ++jr)
                {
                    pk_U[pk_U_cp] ^= (byte)((pk_cp2.getByte() >>> ir) & 1) << jr;
                    pk_cp2.moveNextBytes(NB_BYTES_GFqm);
                }
                ++pk_U_cp;
            }
            if (HFENr8 != 0)
            {
                /* jr=0 */
                pk_U[pk_U_cp] = (byte)((pk_cp2.getWithCheck() >>> ir) & 1);
                pk_cp2.moveNextBytes(NB_BYTES_GFqm);
                for (jr = 1; jr < HFENr8; ++jr)
                {
                    //System.out.println("pk_cp2:" + pk_cp2.getIndex());
                    pk_U[pk_U_cp] ^= (byte)((pk_cp2.getWithCheck() >>> ir) & 1) << jr;
                    pk_cp2.moveNextBytes(NB_BYTES_GFqm);
                }
                ++pk_U_cp;
            }
        }
    }

    void convMQ_UL_gf2(byte[] pk, byte[] pk_U, int j)
    {
        //pk2: pk_U, pk: pk
        int k, nb_bits, i, jj;
        int pk_p = ACCESS_last_equations8 + j * NB_BYTES_EQUATION;
        int pk_U_cp = j * NB_BYTES_EQUATION;
//      convMQ_UL_gf2(pk2 + ACCESS_last_equations8 + j * NB_BYTES_EQUATION, pk_U + j * NB_BYTES_EQUATION);
        /* Constant + x_0*x_0 */
        pk[pk_p] = (byte)(pk_U[pk_U_cp] & 3);
        for (i = 1; i < NB_BYTES_EQUATION; ++i)
        {
            pk[i + pk_p] = 0;
        }
        /* For each row of the output (the first is already done) */
        for (k = 2, i = 2; i <= HFEnv; ++i)
        {
            nb_bits = i;
            /* For each column */
            for (jj = HFEnv - 1; jj >= HFEnv - i; --jj, ++k)
            {
                pk[pk_p + (k >> 3)] ^= ((pk_U[pk_U_cp + (nb_bits >> 3)] >>> (nb_bits & 7)) & 1) << (k & 7);
                nb_bits += jj;
            }
        }
    }

    void convMQS_one_eq_to_hybrid_rep8_comp_gf2(byte[] pk, PointerUnion pk_cp)
    {
        byte[] pk_U = new byte[HFEmr8 * NB_BYTES_EQUATION];
        int i, j;
        //convMQS_one_to_last_mr8_equations_gf2(pk_U,pk);
        convMQS_one_to_last_mr8_equations_gf2(pk_U, pk_cp);
        //convMQS_one_eq_to_hybrid_rep8_gf2(pk, pk_tmp)
        for (j = 0; j < HFEmr8; ++j)
        {
            convMQ_UL_gf2(pk, pk_U, j);
        }
        if (HFEmq8 != 0)
        {
            /* Monomial representation */
            pk_cp.indexReset();
            int pk_p = 0;
            for (i = 0; i < NB_MONOMIAL_PK; ++i)
            {
                for (j = 0; j < HFEmq8; ++j)
                {
                    pk[pk_p] = pk_cp.getByte();
                    pk_p++;
                    pk_cp.moveNextByte();
                }
                /* Jump the coefficients of the HFEmr8 last equations */
                if (HFEmr8 != 0)
                {
                    pk_cp.moveNextByte();
                }
            }
        }
    }

    void convMQS_one_eq_to_hybrid_rep8_uncomp_gf2(byte[] pk, PointerUnion pk_cp)
    {
        byte[] pk_U = new byte[HFEmr8 * NB_BYTES_EQUATION];
        int i, j, k, nb_bits;
        long val = 0;
        convMQS_one_to_last_mr8_equations_gf2(pk_U, pk_cp);
        for (j = 0; j < HFEmr8 - 1; ++j)
        {
            convMQ_UL_gf2(pk, pk_U, j);
        }
        pk_cp.indexReset();

        /* The last equation is smaller because compressed */
//        long val = convMQ_last_UL_gf2(pk2 + ACCESS_last_equations8 + j * NB_BYTES_EQUATION, pk_U + j * NB_BYTES_EQUATION);
        int pk2_cp = ACCESS_last_equations8 + j * NB_BYTES_EQUATION;
        int pk_U_cp = j * NB_BYTES_EQUATION;
        if (HFENr8 != 0 && (HFEmr8 > 1))
        {
            final int SIZE_LAST_EQUATION = ((NB_MONOMIAL_PK - ((HFEmr8 - 1) * HFENr8c) + 7) >> 3);
            /* Constant + x_0*x_0 */
            pk[pk2_cp] = (byte)(pk_U[pk_U_cp] & 3);
            for (i = 1; i < SIZE_LAST_EQUATION; ++i)
            {
                pk[pk2_cp + i] = 0;
            }
            /* For each row of the output (the first is already done) */
            for (k = 2, i = 2; i < HFEnv; ++i)
            {
                nb_bits = i;
                /* For each column */
                for (j = HFEnv - 1; j >= HFEnv - i; --j, ++k)
                {
                    pk[pk2_cp + (k >> 3)] ^= ((pk_U[pk_U_cp + (nb_bits >> 3)] >> (nb_bits & 7)) & 1) << (k & 7);
                    nb_bits += j;
                }
            }
            /* i == HFEnv */
            nb_bits = HFEnv;
            /* For each column */
            for (j = HFEnv - 1; j >= LOST_BITS; --j, ++k)
            {
                pk[pk2_cp + (k >> 3)] ^= ((pk_U[pk_U_cp + (nb_bits >> 3)] >> (nb_bits & 7)) & 1) << (k & 7);
                nb_bits += j;
            }
            for (; j >= 0; --j, ++k)
            {
                val ^= ((long)((pk_U[pk_U_cp + (nb_bits >> 3)] >> (nb_bits & 7)) & 1)) << (LOST_BITS - 1 - j);
                nb_bits += j;
            }
        }
        /* We put the last bits (stored in val) and we put it in the zero padding of each equation (excepted in
        the last since it is not complete since we use its last bits to fill the paddings) */
        pk2_cp = ACCESS_last_equations8 - 1;
        for (j = 0; j < (HFEmr8 - 1); ++j)
        {
            /* Last byte of the equation */
            pk2_cp += NB_BYTES_EQUATION;
            pk[pk2_cp] ^= ((byte)(val >> (j * HFENr8c))) << HFENr8;
        }

        if (HFEmq8 != 0)
        {
            /* Monomial representation */
            pk_cp.indexReset();
            int pk_p = 0;
            for (i = 0; i < NB_MONOMIAL_PK; ++i)
            {
                for (j = 0; j < HFEmq8; ++j)
                {
                    pk[pk_p] = pk_cp.getByte();
                    pk_p++;
                    pk_cp.moveNextByte();
                }
                /* Jump the coefficients of the HFEmr8 last equations */
                if (HFEmr8 != 0)
                {
                    pk_cp.moveNextByte();
                }
            }
        }
    }

    public int crypto_sign_open(byte[] PK, byte[] message, byte[] signature)
    {
        Pointer pk_tmp = new Pointer(1 + NB_WORD_UNCOMP_EQ * HFEmr8);//if (HFEmr8 != 0)
        PointerUnion pk = new PointerUnion(PK);
        int i;
        long val = 0;
        if (HFENr8 != 0 && (HFEmr8 > 1))
        {
            PointerUnion pk_cp = new PointerUnion(pk);
            pk_cp.moveNextBytes(ACCESS_last_equations8 - 1);
            for (i = 0; i < HFEmr8 - 1; ++i)
            {
                /* Last byte of the equation */
                pk_cp.moveNextBytes(NB_BYTES_EQUATION);
                val ^= ((pk_cp.getByte() & 0xFFL) >>> HFENr8) << (i * HFENr8c);
            }
        }
        if (HFEmr8 != 0)
        {
            long cst = 0;
            PointerUnion pk64 = new PointerUnion(pk);
            for (i = 0; i < (HFEmr8 - 1); i++)
            {
                pk64.setByteIndex(ACCESS_last_equations8 + i * NB_BYTES_EQUATION);
                cst ^= convMQ_uncompressL_gf2(new Pointer(pk_tmp, 1 + i * NB_WORD_UNCOMP_EQ), pk64) << i;
            }
            pk64.setByteIndex(ACCESS_last_equations8 + i * NB_BYTES_EQUATION);
            /* The last equation in input is smaller because compressed */
            cst ^= convMQ_last_uncompressL_gf2(new Pointer(pk_tmp, 1 + i * NB_WORD_UNCOMP_EQ), pk64) << i;
            if (HFENr8 != 0 && (HFEmr8 > 1))
            {
                /* Number of lost bits by the zero padding of each equation (without the last) */
                if (HFEnvr == 0)
                {
                    pk_tmp.setXor(1 + (i + 1) * NB_WORD_UNCOMP_EQ - 1, val << (64 - LOST_BITS));
                }
                else if (HFEnvr > LOST_BITS)
                {
                    pk_tmp.setXor(1 + (i + 1) * NB_WORD_UNCOMP_EQ - 1, val << (HFEnvr - LOST_BITS));
                }
                else if (HFEnvr == LOST_BITS)
                {
                    pk_tmp.set(1 + (i + 1) * NB_WORD_UNCOMP_EQ - 1, val);
                }
                else if (HFEnvr < LOST_BITS)
                {
                    pk_tmp.setXor(1 + (i + 1) * NB_WORD_UNCOMP_EQ - 2, val << (64 - (LOST_BITS - HFEnvr)));
                    pk_tmp.set(1 + (i + 1) * NB_WORD_UNCOMP_EQ - 1, val >> (LOST_BITS - HFEnvr));
                }
            }
            cst <<= HFEmr - HFEmr8;
            pk_tmp.set(cst);
        }
        int ret = 0;
        if (HFEmr8 != 0)
        {
            ret = sign_openHFE_huncomp_pk(message, message.length, signature, pk, new PointerUnion(pk_tmp));
        }
        return ret;
    }
}

