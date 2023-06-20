package org.bouncycastle.pqc.crypto.gemss;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Pack;

class GeMSSEngine
{
    private SecureRandom random;
    final int HFEn;// {174, 175, 177, 178, 265, 266, 268, 270, 271, 354, 358, 364, 366, 402, 537, 544}
    final int HFEv;// {11, 12, 13, 14, 15, 18, 20, 21, 22, 23, 24, 25, 26, 29, 32, 33, 35}
    final int HFEDELTA;// {10, 12, 13, 15, 18, 21, 22, 24, 25, 29, 30, 32, 33, 34, 35}
    final int NB_ITE;//{1, 3, 4}
    final int HFEDeg;// {17, 129, 513, 640, 1152}
    //Pair of HFEDegI and HFEDegJ:{(9, 0), (7,0), (4,0), (9, 7), (10, 7)}
    final int HFEDegI;// {4, 7, 9, 10}
    final int HFEDegJ;// {7, 0}
    final int HFEnv;//{186, 187, 189, 190, 192, 193, 277, 285, 288, 289, 291, 292, 295, 387, 390, 393, 396, 399, 420, 563, 576}
    final int HFEm;//{162, 163, 243, 253, 256, 257, 324, 333, 384, 512}
    final int NB_BITS_UINT = 64;
    final int HFEnq;
    final int HFEnr;//{9, 10, 12, 14, 15, 18, 24, 25, 32, 38, 44, 46, 47, 49, 50,}
    int HFE_odd_degree;
    int NB_WORD_GFqn;//{3, 5, 6, 7, 9}
    int NB_WORD_GF2nv;
    int NB_MONOMIAL_VINEGAR;
    int NB_MONOMIAL_PK;
    final int HFEnvq;
    final int HFEnvr;//{0, 1, 3, 6, 9, 12, 15, 21, 29, 32, 35, 36, 39, 51, 58, 59, 61, 62}
    int LTRIANGULAR_NV_SIZE;
    final int LTRIANGULAR_N_SIZE;
    final int SIZE_SEED_SK;
    final int NB_WORD_MUL;//{6, 9, 12, 13, 17}
    int NB_WORD_MMUL;//{6, 9, 12, 13, 17}
    int MQv_GFqn_SIZE;
    final boolean ENABLED_REMOVE_ODD_DEGREE;
    final int MATRIXnv_SIZE;
    /* Number of UINT of matrix m*m in GF(2) */
    final int HFEmq;
    final int HFEmr;//{0, 4, 13, 34, 35, 51, 55}
    int NB_WORD_GF2m;
    final int HFEvq;
    final int HFEvr;
    final int NB_WORD_GFqv;
    final int HFEmq8;//{20, 30, 32, 40, 41, 48, 64}
    final int HFEmr8; //{0, 2, 3, 4, 5, 7}
    final int NB_BYTES_GFqm;
    final int ACCESS_last_equations8;
    final int NB_BYTES_EQUATION;
    final int HFENr8;
    final int NB_WORD_UNCOMP_EQ;
    final int HFENr8c;
    final int LOST_BITS;
    final int NB_WORD_GF2nvm;
    final int SIZE_SIGN_UNCOMPRESSED;
    final int SIZE_DIGEST;
    final int SIZE_DIGEST_UINT;
    final int HFEnvr8;
    final int NB_BYTES_GFqnv;
    final int VAL_BITS_M;
    final long MASK_GF2m;
    final int LEN_UNROLLED_64 = 4;
    int NB_COEFS_HFEPOLY;
    int NB_UINT_HFEVPOLY;
    final int MATRIXn_SIZE;
    final long MASK_GF2n;
    final int NB_BYTES_GFqn;
    private int buffer;
    final int SIZE_ROW;
    final int ShakeBitStrength;
    final int Sha3BitStrength;
    SHA3Digest sha3Digest;
    final int MLv_GFqn_SIZE;
    int II;
    int POW_II;
    int KP;
    int KX;
    int HFEn_1rightmost;
    /* Search the position of the MSB of n-1 */
    int HFEn1h_rightmost;
    Mul_GF2x mul;
    Rem_GF2n rem;
    Pointer Buffer_NB_WORD_MUL;
    Pointer Buffer_NB_WORD_GFqn;

    public GeMSSEngine(int K, int HFEn, int HFEv, int HFEDELTA, int NB_ITE, int HFEDeg, int HFEDegI, int HFEDegJ)
    {
        this.HFEn = HFEn;
        this.HFEv = HFEv;
        this.HFEDELTA = HFEDELTA;
        this.NB_ITE = NB_ITE;
        this.HFEDeg = HFEDeg;
        this.HFEDegI = HFEDegI;
        this.HFEDegJ = HFEDegJ;
        NB_BYTES_GFqn = (HFEn >>> 3) + (((HFEn & 7) != 0) ? 1 : 0);
        SIZE_ROW = HFEDegI + 1;
        HFEnv = HFEn + HFEv;
        HFEnq = HFEn >>> 6;
        HFEnr = HFEn & 63;
        HFEnvq = HFEnv >>> 6;
        HFEnvr = HFEnv & 63;
        SIZE_SEED_SK = K >>> 3;
        NB_WORD_MUL = ((((HFEn - 1) << 1) >>> 6) + 1);
        switch (NB_WORD_MUL)
        {
        case 6: //gemss128, bluegemss128, redgemss128, whitegemss128, cyangemss128, magentagemss128
            mul = new Mul_GF2x.Mul6();
            break;
        case 9: //gemss192, bluegemss192, redgemss192, whitegemss192, cyangemss192, magentagemss192, fgemss128, dualmodems128
            mul = new Mul_GF2x.Mul9();
            break;
        case 12: //gemss256, bluegemss256, redgemss256, whitegemss256, cyangemss256, magentagemss256
            mul = new Mul_GF2x.Mul12();
            break;
        case 13: //fgemss192, dualmodems192
            mul = new Mul_GF2x.Mul13();
            break;
        case 17: //fgemss256, dualmodems256
            mul = new Mul_GF2x.Mul17();
            break;
        }
        int KI = HFEn & 63;
        int KI64 = 64 - KI;
        HFEm = HFEn - HFEDELTA;
        HFEmq = HFEm >>> 6;
        HFEmr = HFEm & 63;
        HFEvq = HFEv >>> 6;
        HFEvr = HFEv & 63;
        NB_WORD_GFqv = HFEvr != 0 ? HFEvq + 1 : HFEvq;
        HFEmq8 = HFEm >>> 3;
        HFEmr8 = HFEm & 7;
        NB_BYTES_GFqm = HFEmq8 + (HFEmr8 != 0 ? 1 : 0);
        NB_WORD_UNCOMP_EQ = ((((HFEnvq * (HFEnvq + 1)) >>> 1) * NB_BITS_UINT) + (HFEnvq + 1) * HFEnvr);
        HFEnvr8 = HFEnv & 7;
        NB_BYTES_GFqnv = (HFEnv >>> 3) + ((HFEnvr8 != 0) ? 1 : 0);
        VAL_BITS_M = Math.min(HFEDELTA + HFEv, 8 - HFEmr8);
        MASK_GF2m = GeMSSUtils.maskUINT(HFEmr);
        MASK_GF2n = GeMSSUtils.maskUINT(HFEnr);
        NB_WORD_GFqn = HFEnq + (HFEnr != 0 ? 1 : 0);
        /* To choose macro for NB_WORD_GFqn*64 bits */
        LTRIANGULAR_N_SIZE = (((HFEnq * (HFEnq + 1)) >>> 1) * NB_BITS_UINT + NB_WORD_GFqn * HFEnr);
        MATRIXn_SIZE = HFEn * NB_WORD_GFqn;
        NB_WORD_GF2nv = HFEnvq + (HFEnvr != 0 ? 1 : 0);
        MATRIXnv_SIZE = HFEnv * NB_WORD_GF2nv;
        LTRIANGULAR_NV_SIZE = (((HFEnvq * (HFEnvq + 1)) >>> 1) * NB_BITS_UINT + NB_WORD_GF2nv * HFEnvr);
        NB_MONOMIAL_VINEGAR = (((HFEv * (HFEv + 1)) >>> 1) + 1);
        NB_MONOMIAL_PK = (((HFEnv * (HFEnv + 1)) >>> 1) + 1);
        MQv_GFqn_SIZE = NB_MONOMIAL_VINEGAR * NB_WORD_GFqn;
        ACCESS_last_equations8 = NB_MONOMIAL_PK * HFEmq8;
        NB_BYTES_EQUATION = (NB_MONOMIAL_PK + 7) >>> 3;
        HFENr8 = NB_MONOMIAL_PK & 7;
        HFENr8c = ((8 - HFENr8) & 7);
        LOST_BITS = (HFEmr8 - 1) * HFENr8c;
        NB_WORD_MMUL = ((((HFEn - 1) << 1) >>> 6) + 1);
        int K1 = 0, K2 = 0, K3, K164 = 0, K264 = 0, K364;
        switch (HFEn)
        {
        case 174://gemss128
            K3 = 13;
            break;
        case 175://bluegemss128, whitegemss128
            K3 = 16;
            break;
        case 177://redgemss128, cyangemss128
            K3 = 8;
            break;
        case 178://magentagemss128
            K3 = 31;
            break;
        case 265://gemss192, bluegemss192
            K3 = 42;
            break;
        case 266://redgemss192,fgemss128,dualmodems128
            K3 = 47;
            break;
        case 268://whitegemss192
            K3 = 25;
            break;
        case 270://cyangemss192
            K3 = 53;
            break;
        case 271://magentagemss192
            K3 = 58;
            break;
        case 354://gemss256
            K3 = 99;
            break;
        case 358://redgemss256, bluegemss256
            K3 = 57;
            break;
        case 364://whitegemss256, cyangemss256
            K3 = 9;
            break;
        case 366://magentagemss256
            K3 = 29;
            break;
        case 402://fgemss192,dualmodems192
            K3 = 171;
            break;
        case 537://fgemss256
            K3 = 10;
            K2 = 2;
            K1 = 1;
            break;
        case 544://dualmodems256
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
            K164 = 64 - K1;
            K264 = 64 - K2;
        }
        K364 = 64 - (K3 & 63);
        if ((HFEDeg & 1) == 0)
        {
            // Set to 1 to remove terms which have an odd degree strictly greater than HFE_odd_degree
            ENABLED_REMOVE_ODD_DEGREE = true;
            /* HFE_odd_degree = 1 + 2^LOG_odd_degree */
            HFE_odd_degree = ((1 << HFEDegI) + 1);
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
            NB_COEFS_HFEPOLY = (2 + HFEDegJ + ((HFEDegI * (HFEDegI - 1)) >>> 1) + HFEDegI);
        }
        else
        {
            ENABLED_REMOVE_ODD_DEGREE = false;
            NB_COEFS_HFEPOLY = (2 + HFEDegJ + ((HFEDegI * (HFEDegI + 1)) >>> 1));
        }
        NB_WORD_GF2m = HFEmq + (HFEmr != 0 ? 1 : 0);
        NB_WORD_GF2nvm = NB_WORD_GF2nv - NB_WORD_GF2m + (HFEmr != 0 ? 1 : 0);
        SIZE_SIGN_UNCOMPRESSED = NB_WORD_GF2nv + (NB_ITE - 1) * NB_WORD_GF2nvm;
        if (K <= 128)
        {
            SIZE_DIGEST = 32;
            SIZE_DIGEST_UINT = 4;
            ShakeBitStrength = 128;
            Sha3BitStrength = 256;
        }
        else if (K <= 192)
        {
            SIZE_DIGEST = 48;
            SIZE_DIGEST_UINT = 6;
            ShakeBitStrength = 256;
            Sha3BitStrength = 384;
        }
        else
        {
            SIZE_DIGEST = 64;
            SIZE_DIGEST_UINT = 8;
            ShakeBitStrength = 256;
            Sha3BitStrength = 512;
        }
        sha3Digest = new SHA3Digest(Sha3BitStrength);
        NB_UINT_HFEVPOLY = (NB_COEFS_HFEPOLY + (NB_MONOMIAL_VINEGAR - 1) + (HFEDegI + 1) * HFEv) * NB_WORD_GFqn;
        MLv_GFqn_SIZE = (HFEv + 1) * NB_WORD_GFqn;
        if (HFEDeg <= 34 || (HFEn > 196 && HFEDeg < 256))
        {
            if (HFEDeg == 17) //redgemss128, redgemss192, redgemss256 magentagemss128 magentagemss192 magentagemss256
            {
                II = 4;
            }
            else //bluegemss192, bluegemss256 cyangemss192 cyangemss256 fgemss128 dualmodems
            {
                II = 6;
            }
            POW_II = 1 << II;
            KP = (HFEDeg >>> II) + ((HFEDeg % POW_II != 0) ? 1 : 0);
            KX = HFEDeg - KP;
        }
        if (K2 != 0)
        {
            if ((HFEn == 544) && (K3 == 128)) //dualmodems256 MASK_GF2n: 00000000FFFFFFFF
            {
                rem = new Rem_GF2n.REM544_PENTANOMIAL_K3_IS_128_GF2X(K1, K2, KI, KI64, K164, K264, MASK_GF2n);
            }
            else //fgemss256 1FFFFFFL
            {
                rem = new Rem_GF2n.REM544_PENTANOMIAL_GF2X(K1, K2, K3, KI, KI64, K164, K264, K364, MASK_GF2n);
            }
        }
        else
        {
            if (HFEn > 256 && HFEn < 289 && K3 > 32 && K3 < 64) //whitegemss192, bluegemss192, redgemss192, magentagemss192, cyangemss192
            {
                rem = new Rem_GF2n.REM288_SPECIALIZED_TRINOMIAL_GF2X(K3, KI, KI64, K364, MASK_GF2n);
            }
            else if (HFEn == 354) //gemss256, whitegemss256, cyangemss256, magentagemss256
            {
                rem = new Rem_GF2n.REM384_SPECIALIZED_TRINOMIAL_GF2X(K3, KI, KI64, K364, MASK_GF2n);
            }
            else if (HFEn == 358) //bluegemss256, redgemss256
            {
                rem = new Rem_GF2n.REM384_SPECIALIZED358_TRINOMIAL_GF2X(K3, KI, KI64, K364, MASK_GF2n);
            }
            else if (HFEn == 402) //fgemss192, dualmodems192
            {
                rem = new Rem_GF2n.REM402_SPECIALIZED_TRINOMIAL_GF2X(K3, KI, KI64, K364, MASK_GF2n);
            }
            else
            {
                switch (NB_WORD_MUL)
                {
                case 6: //gemss128, bluegemss128, redgemss128, whitegemss128, magentagemss128
                    rem = new Rem_GF2n.REM192_SPECIALIZED_TRINOMIAL_GF2X(K3, KI, KI64, K364, MASK_GF2n);
                    break;
                case 9: //whitegemss192, bluegemss192
                    rem = new Rem_GF2n.REM288_SPECIALIZED_TRINOMIAL_GF2X(K3, KI, KI64, K364, MASK_GF2n);
                    break;
                case 12:
                    rem = new Rem_GF2n.REM384_TRINOMIAL_GF2X(K3, KI, KI64, K364, MASK_GF2n);
                }
            }
        }
        Buffer_NB_WORD_MUL = new Pointer(NB_WORD_MUL);
        Buffer_NB_WORD_GFqn = new Pointer(NB_WORD_GFqn);
        HFEn_1rightmost = 31;
        int e = HFEn - 1;
        while ((e >>> HFEn_1rightmost) == 0)
        {
            --HFEn_1rightmost;
        }
        e = (HFEn + 1) >>> 1;
        /* Search the position of the MSB of n-1 */
        HFEn1h_rightmost = 31;
        while ((e >>> HFEn1h_rightmost) == 0)
        {
            --HFEn1h_rightmost;
        }
        --HFEn1h_rightmost;
    }

    void genSecretMQS_gf2_opt(Pointer MQS, Pointer F)
    {
        Pointer a_vec_k;
        Pointer a_vec_kp, buf_k, buf_kp;
        Pointer F_cp;
        Pointer tmp3 = new Pointer(NB_WORD_GFqn);
        int i, j, k, kp, a_vec_kp_orig, buf_k_orig, a_vec_k_orig, buf_kp_orig;
        /* Vector with linear terms of F */
        Pointer F_lin = new Pointer((HFEDegI + 1) * (HFEv + 1) * NB_WORD_GFqn);
        F_cp = new Pointer(F, MQv_GFqn_SIZE);
        for (i = 0; i <= HFEDegI; ++i)
        {
            for (k = 0; k <= HFEv; ++k)
            {
                F_lin.copyFrom((k * (HFEDegI + 1) + i) * NB_WORD_GFqn, F_cp, 0, NB_WORD_GFqn);
                F_cp.move(NB_WORD_GFqn);
            }
            F_cp.move(i * NB_WORD_GFqn);
        }
        /* Precompute alpha_vec is disabled in the submission */
        Pointer alpha_vec = new Pointer(SIZE_ROW * (HFEn - 1) * NB_WORD_GFqn);
        /* Matrix in GF(2^n) with HFEn-1 rows and (HFEDegI+1) columns */
        /* calloc is useful when it initialises a multiple precision element to 1 */
        for (i = 1; i < HFEn; ++i)
        {
            /* j=0: a^i */
            alpha_vec.set(i >>> 6, 1L << (i & 63));
            /* Compute (a^i)^(2^j) */
            for (j = 0; j < HFEDegI; ++j)
            {
                sqr_gf2n(alpha_vec, NB_WORD_GFqn, alpha_vec, 0);
                alpha_vec.move(NB_WORD_GFqn);
            }
            alpha_vec.move(NB_WORD_GFqn);
        }
        alpha_vec.indexReset();
        /* Constant: copy the first coefficient of F in MQS */
        MQS.copyFrom(F, NB_WORD_GFqn);
        F.move(MQv_GFqn_SIZE);
        MQS.move(NB_WORD_GFqn);
        /* Precompute an other table */
        Pointer buf = new Pointer(HFEDegI * HFEn * NB_WORD_GFqn);
        special_buffer(buf, F, alpha_vec);
        /* k=0 */
        buf_k = new Pointer(buf);
        /* kp=0 */
        buf_kp = new Pointer(buf);
        /* x_0*x_0: quadratic terms of F */
        /* i=0 */
        MQS.copyFrom(buf_kp, NB_WORD_GFqn);
        buf_kp.move(NB_WORD_GFqn);
        MQS.setXorMatrix_NoMove(buf_kp, NB_WORD_GFqn, HFEDegI - 1);
        /* At this step, buf_kp corresponds to kp=1 */
        /* x_0: linear terms of F */
        F_cp.changeIndex(F_lin);
        /* X^(2^i) */
        MQS.setXorMatrix(F_cp, NB_WORD_GFqn, HFEDegI + 1);
        /* kp=1 (because kp=0 is not stored, it is just (1,1,1,...,1) */
        /* +NB_WORD_GFqn to jump (alpha^kp)^(2^0) */
        a_vec_kp = new Pointer(alpha_vec, NB_WORD_GFqn);
        /* k=0: x_0 x_kp */
        for (kp = 1; kp < HFEn; ++kp)
        {
            /* dot_product(a_vec_kp, buf_k) */
            dotProduct_gf2n(MQS, a_vec_kp, buf_k, HFEDegI);
            a_vec_kp.move(SIZE_ROW * NB_WORD_GFqn);
            /* dot_product(a_vec_k=(1,1,...,1) , buf_kp) */
            MQS.setXorMatrix(buf_kp, NB_WORD_GFqn, HFEDegI);
        }
        /* Vinegar variables */
        for (; kp < HFEnv; ++kp)
        {
            MQS.copyFrom(F_cp, NB_WORD_GFqn);
            F_cp.move(NB_WORD_GFqn);
            MQS.setXorMatrix(F_cp, NB_WORD_GFqn, HFEDegI);
        }
        /* k=0 becomes k=1 */
        /* +NB_WORD_GFqn to jump (alpha^k)^(2^0) */
        a_vec_k = new Pointer(alpha_vec, NB_WORD_GFqn);
        Pointer acc = new Pointer(NB_WORD_MUL);
        /* Compute the term x_k x_kp */
        for (k = 1; k < HFEn; ++k)
        {
            /* k=0 becomes k=1 */
            buf_k.move(HFEDegI * NB_WORD_GFqn);
            /* kp=k: x_k + x_k*x_k */
            a_vec_kp.changeIndex(a_vec_k);
            buf_kp.changeIndex(buf_k);
            /* Term X^(2^0) of F */
            mul.mul_gf2x(Buffer_NB_WORD_MUL, F_lin, new Pointer(a_vec_kp, -NB_WORD_GFqn));
            /* dot_product(a_vec_k,buf_k) */
            /* i=0 */
            for (i = 1; i <= HFEDegI; ++i)
            {
                /* Next linear term of F: X^(2^i) */
                tmp3.setRangeFromXor(0, buf_kp, 0, F_lin, i * NB_WORD_GFqn, NB_WORD_GFqn);
                mul_xorrange(Buffer_NB_WORD_MUL, tmp3, a_vec_kp);
                buf_kp.move(NB_WORD_GFqn);
                a_vec_kp.move(NB_WORD_GFqn);
            }
            /* Monic case */
            /* To jump (alpha^kp)^(2^0) */
            a_vec_kp.move(NB_WORD_GFqn);
            rem_gf2n(MQS, 0, Buffer_NB_WORD_MUL);
            MQS.move(NB_WORD_GFqn);
            /* x_k*x_kp */
            for (kp = k + 1; kp < HFEn; ++kp)
            {
                a_vec_kp_orig = a_vec_kp.getIndex();
                buf_k_orig = buf_k.getIndex();
                a_vec_k_orig = a_vec_k.getIndex();
                buf_kp_orig = buf_kp.getIndex();
                /* i=0 */
                mul_move(acc, a_vec_kp, buf_k);
                for_mul_xorrange_move(acc, a_vec_kp, buf_k, HFEDegI - 1);
                for_mul_xorrange_move(acc, a_vec_k, buf_kp, HFEDegI);
                rem_gf2n(MQS, 0, acc);
                a_vec_kp.changeIndex(a_vec_kp_orig + SIZE_ROW * NB_WORD_GFqn);
                buf_k.changeIndex(buf_k_orig);
                a_vec_k.changeIndex(a_vec_k_orig);
                buf_kp.changeIndex(buf_kp_orig + HFEDegI * NB_WORD_GFqn);
                MQS.move(NB_WORD_GFqn);
            }
            /* Vinegar variables */
            F_cp.changeIndex(F_lin);
            a_vec_k.move(-NB_WORD_GFqn);
            for (; kp < HFEnv; ++kp)
            {
                F_cp.move((HFEDegI + 1) * NB_WORD_GFqn);
                dotProduct_gf2n(MQS, a_vec_k, F_cp, HFEDegI + 1);
                MQS.move(NB_WORD_GFqn);
            }
            a_vec_k.move(NB_WORD_GFqn + SIZE_ROW * NB_WORD_GFqn);
            /* k becomes k+1 */
        }
        /* MQS with v vinegar variables */
        F.move(NB_WORD_GFqn - MQv_GFqn_SIZE);
        MQS.copyFrom(F, NB_WORD_GFqn * (NB_MONOMIAL_VINEGAR - 1));
        MQS.indexReset();
        F.indexReset();
    }

    private void special_buffer(Pointer buf, Pointer F, Pointer alpha_vec)
    {
        int i, k;
        int F_orig = F.getIndex();
        /* Special case: alpha^0 */
        /* F begins to X^3, the first "quadratic" term */
        F.move((NB_WORD_GFqn * (HFEv + 1)) << 1);
        /* X^3 */
        buf.copyFrom(F, NB_WORD_GFqn);
        buf.move(NB_WORD_GFqn);
        /* X^5: we jump X^4 because it is linear */
        Pointer F_cp = new Pointer(F, NB_WORD_GFqn * (HFEv + 2));
        /* A_i,j X^(2^i + 2^j) */
        /* min(L,SIZE_ROW-1) */
        for (i = 2; i < SIZE_ROW - 1; ++i)
        {
            /* j=0: A_i,0 */
            copy_move_matrix_move(buf, F_cp, i - 1);
        }
        if (ENABLED_REMOVE_ODD_DEGREE)
        {
            for (; i < (SIZE_ROW - 1); ++i)
            {
                /* j=0 is removed because the term is odd */
                /* j=1: A_i,1 */
                copy_move_matrix_move(buf, F_cp, i - 2);
            }
        }
        /* Monic case */
        buf.set1_gf2n(0, NB_WORD_GFqn);
        buf.setXorMatrix(F_cp, NB_WORD_GFqn, HFEDegJ);
        /* Squares of (alpha^(k+1)) */
        for (k = 0; k < (HFEn - 1); ++k)
        {
            /* X^3: i=1,j=0 */
            mul_gf2n(buf, alpha_vec, F);
            buf.move(NB_WORD_GFqn);
            /* X^5: we jump X^4 because it is linear */
            F_cp.changeIndex(F, NB_WORD_GFqn * (HFEv + 2));
            /* A_i,j X^(2^i + 2^j) */
            for (i = 2; i < HFEDegI; ++i)
            {
                dotproduct_move_move(buf, F_cp, alpha_vec, i);
            }
            if (ENABLED_REMOVE_ODD_DEGREE)
            {
                alpha_vec.move(NB_WORD_GFqn);
                for (; i < SIZE_ROW - 1; ++i)
                {
                    dotproduct_move_move(buf, F_cp, alpha_vec, i - 1);
                }
                alpha_vec.move(-NB_WORD_GFqn);
            }
            /* j=0: A_i,0 */
            if (HFEDegJ == 0)
            {
                /* Monic case */
                buf.copyFrom(alpha_vec, NB_WORD_GFqn);
                buf.move(NB_WORD_GFqn);
                /* To change the row of alpha_vec */
                alpha_vec.move(SIZE_ROW * NB_WORD_GFqn);
            }
            else
            {
                dotProduct_gf2n(buf, alpha_vec, F_cp, HFEDegJ);
                /* j=HFEDegJ: monic case */
                alpha_vec.move(HFEDegJ * NB_WORD_GFqn);
                buf.setXorRange_SelfMove(alpha_vec, NB_WORD_GFqn);
                /* To change the row of alpha_vec */
                alpha_vec.move((SIZE_ROW - HFEDegJ) * NB_WORD_GFqn);
            }
        }
        buf.indexReset();
        F.changeIndex(F_orig);
        alpha_vec.indexReset();
    }

    private void copy_move_matrix_move(Pointer buf, Pointer F_cp, int len)
    {
        buf.copyFrom(F_cp, NB_WORD_GFqn);
        F_cp.move(NB_WORD_GFqn);
        buf.setXorMatrix(F_cp, NB_WORD_GFqn, len);
        /* To jump a linear term X^(2^i) */
        F_cp.move(NB_WORD_GFqn * (HFEv + 1));
    }

    private void dotproduct_move_move(Pointer buf, Pointer F_cp, Pointer alpha_vec, int len)
    {
        dotProduct_gf2n(buf, alpha_vec, F_cp, len);
        buf.move(NB_WORD_GFqn);
        /* To jump quadratic terms + a linear term X^(2^i) */
        F_cp.move((len + HFEv + 1) * NB_WORD_GFqn);
    }

    private void dotProduct_gf2n(Pointer res, Pointer vec_x, Pointer vec_y, int len)
    {
        Pointer tmp_mul = new Pointer(NB_WORD_MUL);
        int vec_x_orig = vec_x.getIndex();
        int vec_y_orig = vec_y.getIndex();
        /* i=0 */
        mul_move(tmp_mul, vec_x, vec_y);
        for_mul_xorrange_move(tmp_mul, vec_x, vec_y, len - 1);
        rem_gf2n(res, 0, tmp_mul);
        vec_x.changeIndex(vec_x_orig);
        vec_y.changeIndex(vec_y_orig);
    }

    /* Function mul in GF(2^x), then modular reduction */
    void mul_gf2n(Pointer P, Pointer A, int AOff, Pointer B)
    {
        int A_orig = A.getIndex();
        A.move(AOff);
        mul.mul_gf2x(Buffer_NB_WORD_MUL, A, B);
        A.changeIndex(A_orig);
        rem_gf2n(P, 0, Buffer_NB_WORD_MUL);
    }

    void mul_gf2n(Pointer P, Pointer A, Pointer B)
    {
        mul.mul_gf2x(Buffer_NB_WORD_MUL, A, B);
        rem_gf2n(P, 0, Buffer_NB_WORD_MUL);
    }

    void for_mul_xorrange_move(Pointer res, Pointer A, Pointer B, int len)
    {
        for (int i = 0; i < len; ++i)
        {
            mul.mul_gf2x_xor(res, A, B);
            A.move(NB_WORD_GFqn);
            B.move(NB_WORD_GFqn);
        }
    }

    void mul_move(Pointer res, Pointer A, Pointer B)
    {
        mul.mul_gf2x(res, A, B);
        A.move(NB_WORD_GFqn);
        B.move(NB_WORD_GFqn);
    }

    public void mul_xorrange(Pointer res, Pointer A, Pointer B)
    {
        mul.mul_gf2x_xor(res, A, B);
    }

    public void mul_rem_xorrange(Pointer res, Pointer A, Pointer B)
    {
        mul.mul_gf2x(Buffer_NB_WORD_MUL, A, B);
        rem.rem_gf2n_xor(res.array, res.cp, Buffer_NB_WORD_MUL.array);
    }

    public void mul_rem_xorrange(Pointer res, Pointer A, Pointer B, int b_cp)
    {
        int B_orig = B.getIndex();
        B.move(b_cp);
        mul.mul_gf2x(Buffer_NB_WORD_MUL, A, B);
        rem.rem_gf2n_xor(res.array, res.cp, Buffer_NB_WORD_MUL.array);
        B.changeIndex(B_orig);
    }

    private void rem_gf2n(Pointer P, int p_cp, Pointer Pol)
    {
        p_cp += P.getIndex();
        rem.rem_gf2n(P.array, p_cp, Pol.array);
    }

    /* Function sqr in GF(2^x), then modular reduction */
    private void sqr_gf2n(Pointer C, int c_shift, Pointer A, int a_shift)
    {
        a_shift += A.cp;
        mul.sqr_gf2x(Buffer_NB_WORD_MUL.array, A.array, a_shift);
        rem_gf2n(C, c_shift, Buffer_NB_WORD_MUL);
    }

    private void sqr_gf2n(Pointer C, Pointer A)
    {
        mul.sqr_gf2x(Buffer_NB_WORD_MUL.array, A.array, A.cp);
        rem.rem_gf2n(C.array, C.cp, Buffer_NB_WORD_MUL.array);
    }

    void cleanLowerMatrix(Pointer L, FunctionParams cleanLowerMatrix)
    {
        int nq, nr;
        int iq;
        switch (cleanLowerMatrix)
        {
        case N:
            nq = HFEnq;
            nr = HFEnr;
            break;
        case NV:
            nq = HFEnvq;
            nr = HFEnvr;
            break;
        default:
            throw new IllegalArgumentException("");
        }
        Pointer L_cp = new Pointer(L);
        /* for each row */
        for (iq = 1; iq <= nq; ++iq)
        {
            for_and_xor_shift_incre_move(L_cp, iq, NB_BITS_UINT);
            /* Next column */
            L_cp.moveIncremental();
        }
        /* iq = HFEnq */
        for_and_xor_shift_incre_move(L_cp, iq, nr);
    }

    private void for_and_xor_shift_incre_move(Pointer L_cp, int iq, int len)
    {
        long mask = 0;
        for (int ir = 0; ir < len; ++ir)
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
        int i, iq, j;
        int outloopbound, innerloopbound, nextrow, ifCondition, endOfU;
        switch (imluParams)
        {
        case NV:
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
        Sinv_cpi = new Pointer(S);
        Sinv_cpj = new Pointer(S);
        /* for each row of S and of S_inv, excepted the last block */
        for (i = 0, iq = 0; iq < outloopbound; ++iq)
        {
            i = loop_xor_loop_move_xorandmask_move(Sinv_cpi, Sinv_cpj, L_cpj, L, i, iq, NB_BITS_UINT, innerloopbound, nextrow);
            /* Next column */
            L.moveIncremental();
        }
        if (ifCondition > 1)
        {
            loop_xor_loop_move_xorandmask_move(Sinv_cpi, Sinv_cpj, L_cpj, L, i, iq, ifCondition - 1, innerloopbound, nextrow);
            /* ir = HFEnvr-1 */
            Sinv_cpi.setXor(iq, 1L << (ifCondition - 1));
            Sinv_cpi.move(nextrow);
        }
        else if (ifCondition == 1)
        {
            /* ir = 0 */
            Sinv_cpi.set(iq, 1L);
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
                Sinv_cpj.setXorRangeAndMask(Sinv_cpi, nextrow, -(((U.get(j >>> 6)) >>> (j & 63)) & 1L));
                /* next row */
                Sinv_cpj.move(nextrow);
            }
        }
    }

    private int loop_xor_loop_move_xorandmask_move(Pointer Sinv_cpi, Pointer Sinv_cpj, Pointer L_cpj, Pointer L, int i,
                                                   int iq, int len, int innerloopbound, int nextrow)
    {
        int j, ir;
        for (ir = 0; ir < len; ++ir, ++i)
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
                Sinv_cpj.setXorRangeAndMask(Sinv_cpi, iq + 1, -((L_cpj.get() >>> ir) & 1L));
            }
            /* Next row */
            Sinv_cpi.move(nextrow);
            L.move(iq + 1);
        }
        return i;
    }

    enum FunctionParams
    {
        NV,
        V,
        N,
        M
    }

    void vecMatProduct(Pointer res, Pointer vec, Pointer S_orig, FunctionParams vecMatProduct)
    {
        int gf2_len, S_cp_increase, loopir_param, nq;
        long bit_ir;
        int iq = 0, ir = 0;
        Pointer S = new Pointer(S_orig);
        switch (vecMatProduct)
        {
        case NV:
            res.setRangeClear(0, NB_WORD_GF2nv);
            nq = HFEnvq;
            gf2_len = NB_WORD_GF2nv;
            S_cp_increase = NB_WORD_GF2nv;
            break;
        case V:
            res.setRangeClear(0, NB_WORD_GFqn);
            gf2_len = NB_WORD_GFqn;
            S_cp_increase = NB_WORD_GFqn;
            nq = HFEvq;
            break;
        case N:
            res.setRangeClear(0, NB_WORD_GFqn);
            gf2_len = NB_WORD_GFqn;
            S_cp_increase = NB_WORD_GFqn;
            nq = HFEnq;
            break;
        case M:
            res.setRangeClear(0, NB_WORD_GF2m);//removal causes bugs in dualmodems256
            nq = HFEnq;
            gf2_len = NB_WORD_GF2m;
            S_cp_increase = NB_WORD_GFqn;
            break;
        default:
            throw new IllegalArgumentException("Invalid input for vecMatProduct");
        }
        /* for each bit of vec excepted the last block */
        for (; iq < nq; ++iq)
        {
            bit_ir = vec.get(iq);
            for (; ir < 64; ++ir)
            {
                res.setXorRangeAndMask(S, gf2_len, -(bit_ir & 1L));
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
            if (HFEnvr == 0)
            {
                return;
            }
            bit_ir = vec.get(HFEnvq);
            loopir_param = HFEnvr;
            break;
        case V:
            if (HFEvr == 0)
            {
                return;
            }
            bit_ir = vec.get(HFEvq);
            loopir_param = HFEvr;
            break;
        case N:
        case M:
            bit_ir = vec.get(HFEnq);
            loopir_param = HFEnr;
            break;
        default:
            throw new IllegalArgumentException("Invalid input for vecMatProduct");
        }
        for (; ir < loopir_param; ++ir)
        {
            res.setXorRangeAndMask(S, gf2_len, -(bit_ir & 1L));
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
     * (because pk is cast in 64-bit, and the last memory access requires that
     * is allocated a multiple of 64 bits).
     * @remark Constant-time implementation.
     */
    private long convMQ_uncompressL_gf2(Pointer pk2, PointerUnion pk)
    {
        int nb_bits;
        PointerUnion pk64 = new PointerUnion(pk);
        nb_bits = for_setpk2_end_move_plus(pk2, pk64, HFEnvq);
        if (HFEnvr != 0) //except redgemss128
        {
            setPk2Value(pk2, pk64, nb_bits, HFEnvq, HFEnvr + 1);
        }
        /* Constant */
        return pk.get() & 1;
    }

    private int setPk2Value(Pointer pk2, PointerUnion pk64, int nb_bits, int iq, int len)
    {
        int ir;
        for (ir = 1; ir < len; ++ir)
        {
            if ((nb_bits & 63) != 0)
            {
                pk2.setRangePointerUnion(pk64, iq, nb_bits & 63);
                pk2.set(iq, pk64.get(iq) >>> (nb_bits & 63));
                if (((nb_bits & 63) + ir) > 64)
                {
                    pk2.setXor(iq, pk64.get(iq + 1) << (64 - (nb_bits & 63)));
                }
                if (((nb_bits & 63) + ir) >= 64)
                {
                    pk64.moveIncremental();
                }
            }
            else
            {
                pk2.setRangePointerUnion(pk64, iq + 1);
            }
            pk64.move(iq);
            /* 0 padding on the last word */
            pk2.setAnd(iq, (1L << ir) - 1L);
            pk2.move(iq + 1);
            nb_bits += (iq << 6) + ir;
        }
        return nb_bits;
    }

    private void setPk2_endValue(Pointer pk2, PointerUnion pk64, int nb_bits, int iq)
    {
        /* ir=64 */
        if ((nb_bits & 63) != 0)
        {
            pk2.setRangePointerUnion(pk64, iq + 1, nb_bits & 63);
        }
        else
        {
            pk2.setRangePointerUnion(pk64, iq + 1);
        }
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
        k = HFEnv - 1;
        final int HFEnvqm1 = k >>> 6;
        final int HFEnvrm1 = k & 63;
        nb_bits = for_setpk2_end_move_plus(pk2, pk64, HFEnvqm1);
        if (HFEnvrm1 != 0)
        {
            nb_bits = setPk2Value(pk2, pk64, nb_bits, HFEnvqm1, HFEnvrm1 + 1);
        }
        /* Last row */
        /* The size of the last row is HFEnv-LOST_BITS bits */
        k = HFEnv - LOST_BITS;
        final int LAST_ROW_Q = k >>> 6;
        final int LAST_ROW_R = k & 63;
        iq = LAST_ROW_Q;
        long end;
        if (LAST_ROW_R != 0)
        {
            ir = LAST_ROW_R;
            if ((nb_bits & 63) != 0)
            {
                if ((((NB_MONOMIAL_PK - LOST_BITS + 7) >>> 3) & 7) != 0)//Except cyangemss192, magentagemss192
                {
                    final int NB_WHOLE_BLOCKS = ((HFEnv - ((64 - ((NB_MONOMIAL_PK - LOST_BITS - HFEnvr) & 63)) & 63)) >>> 6);
                    pk2.setRangePointerUnion_Check(pk64, NB_WHOLE_BLOCKS, nb_bits);
                    k = NB_WHOLE_BLOCKS;
                    pk2.set(k, pk64.getWithCheck(k) >>> (nb_bits & 63));
                    if (NB_WHOLE_BLOCKS < LAST_ROW_Q)
                    {
                        end = pk64.getWithCheck(k + 1);
                        pk2.setXor(k, end << (64 - (nb_bits & 63)));
                        pk2.set(k + 1, end >>> (nb_bits & 63));
                    }
                    else if (((nb_bits & 63) + ir) > 64)
                    {
                        pk2.setXor(k, pk64.getWithCheck(k + 1) << (64 - (nb_bits & 63)));
                    }
                }
                else
                {
                    pk2.setRangePointerUnion(pk64, iq, nb_bits & 63);
                    pk2.set(iq, pk64.get(iq) >>> (nb_bits & 63));
                    if (((nb_bits & 63) + ir) > 64)
                    {
                        pk2.setXor(iq, pk64.get(iq + 1) << (64 - (nb_bits & 63)));
                    }
                }
            }
            else
            {
                if ((((NB_MONOMIAL_PK - LOST_BITS + 7) >>> 3) & 7) != 0)
                {
                    pk2.setRangePointerUnion(pk64, iq);
                    pk2.set(iq, pk64.getWithCheck(iq));
                }
                else
                {
                    pk2.setRangePointerUnion(pk64, iq + 1);
                }
            }
        }
        else if (LAST_ROW_Q != 0)
        {
            if ((nb_bits & 63) != 0)
            {
                if ((((NB_MONOMIAL_PK - LOST_BITS + 7) >>> 3) & 7) != 0)
                {
                    pk2.setRangePointerUnion(pk64, iq - 1, nb_bits & 63);
                    k = iq - 1;
                    pk2.set(k, pk64.get(k) >>> (nb_bits & 63));
                    pk2.setXor(k, pk64.getWithCheck(k + 1) << (64 - (nb_bits & 63)));
                }
                else
                {
                    pk2.setRangePointerUnion(pk64, iq, nb_bits & 63);
                }
            }
            else
            {
                pk2.setRangePointerUnion(pk64, iq);
            }
        }
        /* Constant */
        return pk.get() & 1L;
    }

    private int for_setpk2_end_move_plus(Pointer pk2, PointerUnion pk64, int len)
    {
        int nb_bits = 1;
        /* For each row */
        for (int iq = 0; iq < len; ++iq)
        {
            nb_bits = setPk2Value(pk2, pk64, nb_bits, iq, 64);
            setPk2_endValue(pk2, pk64, nb_bits, iq);
            pk64.move(iq + 1);
            pk2.move(iq + 1);
            nb_bits += (iq + 1) << 6;
        }
        return nb_bits;
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
        Pointer sm = new Pointer(SIZE_SIGN_UNCOMPRESSED);
        Pointer Si_tab = new Pointer(NB_WORD_GF2nv);
        Pointer Si1_tab = new Pointer(NB_WORD_GF2nv);
        /* Copy of pointer */
        Pointer Si = new Pointer(Si_tab);
        Pointer Si1 = new Pointer(Si1_tab);
        /* Vector of D_1, ..., D_(NB_ITE) */
        byte[] hash = new byte[64];
        Pointer D = new Pointer(NB_ITE * SIZE_DIGEST_UINT);
        int i, index, m_cp = 0;
        long cst = hpk.get();
        /* We jump the constant (stored on 8 bytes) */
        hpk.move(1);
        uncompress_signHFE(sm, sm8);
        /* Compute H1 = H(m), the m first bits are D1 */
        getSHA3Hash(D, 0, 64, m, m_cp, len, hash);
        for (i = 1; i < NB_ITE; ++i)
        {
            /* Compute Hi = H(H_(i-1)), the m first bits are Di */
            getSHA3Hash(D, i * SIZE_DIGEST_UINT, 64, hash, 0, SIZE_DIGEST, hash);
            /* Clean the previous hash (= extract D_(i-1) from H_(i-1)) */
            D.setAnd(SIZE_DIGEST_UINT * (i - 1) + NB_WORD_GF2m - 1, MASK_GF2m);
        }
        /* Clean the previous hash (= extract D_(i-1) from H_(i-1)) */
        D.setAnd(SIZE_DIGEST_UINT * (i - 1) + NB_WORD_GF2m - 1, MASK_GF2m);
        /* Compute p(S_(NB_IT),X_(NB_IT)) */
        evalMQShybrid8_uncomp_nocst_gf2_m(Si, sm, pk, hpk);
        Si.setXor(HFEmq, cst);
        for (i = NB_ITE - 1; i > 0; --i)
        {
            /* Compute Si = xor(p(S_i+1,X_i+1),D_i+1) */
            Si.setXorRange(D, i * SIZE_DIGEST_UINT, NB_WORD_GF2m);
            /* Compute Si||Xi */
            index = NB_WORD_GF2nv + (NB_ITE - 1 - i) * NB_WORD_GF2nvm;
            Si.setAnd(NB_WORD_GF2m - 1, MASK_GF2m);
            /* Concatenation(Si,Xi): the intersection between S1 and X1 is not null */
            Si.setXor(NB_WORD_GF2m - 1, sm.get(index));
            if (NB_WORD_GF2nvm != 1)
            {
                Si.copyFrom(NB_WORD_GF2m, sm, ++index, NB_WORD_GF2nvm - 1);
            }
            /* Compute p(Si,Xi) */
            evalMQShybrid8_uncomp_nocst_gf2_m(Si1, Si, pk, hpk);
            Si1.setXor(HFEmq, cst);
            /* Permutation of pointers */
            Si1.swap(Si);
        }
        /* D1'' == D1 */
        return Si.isEqual_nocst_gf2(D, NB_WORD_GF2m);
    }

    private void getSHA3Hash(Pointer output, int outOff, int outLength, byte[] input, int inOff, int inputLenth, byte[] hash)
    {
        sha3Digest.update(input, inOff, inputLenth);
        sha3Digest.doFinal(hash, 0);
        output.fill(outOff, hash, 0, outLength);
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
        evalMQSnocst8_quo_gf2(res, x, mq_quo);
        if (HFEmr < 8)
        {
            res.set(HFEmq, 0);
        }
        for (int i = HFEmr - HFEmr8; i < HFEmr; ++i)
        {
            res.setXor(HFEmq, evalMQnocst_unrolled_no_simd_gf2(x, mq_rem) << i);
            mq_rem.move(NB_WORD_UNCOMP_EQ);
        }
    }

    /* Uncompress the signature */
    private void uncompress_signHFE(Pointer sm, byte[] sm8)
    {
        PointerUnion sm64 = new PointerUnion(sm);
        final int MASK8_GF2nv = (1 << HFEnvr8) - 1;
        /* Take the (n+v) first bits */
        sm64.fillBytes(0, sm8, 0, NB_BYTES_GFqnv);
        /* Clean the last byte */
        if (HFEnvr8 != 0) //except bluegemss192, redgemss128
        {
            sm64.setAndByte(NB_BYTES_GFqnv - 1, MASK8_GF2nv);
        }
        /* Take the (Delta+v)*(nb_ite-1) bits */
        int k1, k2, nb_rem2, nb_rem_m, val_n, nb_rem;
        /* HFEnv bits are already extracted from sm8 */
        int nb_bits = HFEnv;
        sm64.moveNextBytes((NB_WORD_GF2nv << 3) + (HFEmq8 & 7));
        for (k1 = 1; k1 < NB_ITE; ++k1)
        {
            /* Number of bits to complete the byte of sm8, in [0,7] */
            val_n = Math.min((HFEDELTA + HFEv), ((8 - (nb_bits & 7)) & 7));
            /* First byte of sm8 */
            if ((nb_bits & 7) != 0)
            {
                sm64.setXorByte(((sm8[nb_bits >>> 3] & 0xFF) >>> (nb_bits & 7)) << HFEmr8);
                /* Number of bits to complete the first byte of sm8 */
                nb_rem = val_n - VAL_BITS_M;
                if (nb_rem >= 0)
                {
                    /* We take the next byte since we used VAL_BITS_M bits */
                    sm64.moveNextByte();
                }
                if (nb_rem > 0)
                {
                    nb_bits += VAL_BITS_M;
                    sm64.setXorByte((sm8[nb_bits >>> 3] & 0xFF) >>> (nb_bits & 7));
                    nb_bits += nb_rem;
                }
                else
                {
                    nb_bits += val_n;
                }
            }
            /* Other bytes of sm8 */
            nb_rem2 = (HFEDELTA + HFEv) - val_n;
            /*nb_rem2 can be zero only in this case */
            /* Number of bits used of sm64, mod 8 */
            nb_rem_m = (HFEm + val_n) & 7;
            /* Other bytes */
            if (nb_rem_m != 0)
            {
                /* -1 to take the ceil of /8, -1 */
                for (k2 = 0; k2 < ((nb_rem2 - 1) >>> 3); ++k2)
                {
                    sm64.setXorByte((sm8[nb_bits >>> 3] & 0xFF) << nb_rem_m);
                    sm64.moveNextByte();
                    sm64.setXorByte((sm8[nb_bits >>> 3] & 0xFF) >>> (8 - nb_rem_m));
                    nb_bits += 8;
                }
                /* The last byte of sm8, between 1 and 8 bits to put */
                sm64.setXorByte((sm8[nb_bits >>> 3] & 0xFF) << nb_rem_m);
                sm64.moveNextByte();
                /* nb_rem2 between 1 and 8 bits */
                nb_rem2 = ((nb_rem2 + 7) & 7) + 1;
                if (nb_rem2 > (8 - nb_rem_m))
                {
                    sm64.setByte((sm8[nb_bits >>> 3] & 0xFF) >>> (8 - nb_rem_m));
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
            /* Clean the last byte */
            if (HFEnvr8 != 0)
            {
                sm64.setAndByte(-1, MASK8_GF2nv);
            }
            /* We complete the word. Then we search the first byte. */
            sm64.moveNextBytes(((8 - (NB_BYTES_GFqnv & 7)) & 7) + (HFEmq8 & 7));
        }
    }

    private void evalMQSnocst8_quo_gf2(Pointer c, Pointer m, PointerUnion pk_orig)
    {
        long xi, xj;
        int iq, ir, i = HFEnv, jq;
        final int NB_EQ = (HFEm >>> 3) != 0 ? ((HFEm >>> 3) << 3) : HFEm;
        final int NB_BYTES_EQ = (NB_EQ & 7) != 0 ? ((NB_EQ >>> 3) + 1) : (NB_EQ >>> 3);
        final int NB_WORD_EQ = (NB_BYTES_EQ >>> 3) + ((NB_BYTES_EQ & 7) != 0 ? 1 : 0);
        /* Constant cst_pk */
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
                    pk.moveNextBytes(NB_BYTES_EQ);
                    xj = xi >>> 1;
                    LOOPJR_UNROLLED_64(c, pk, ir + 1, NB_BITS_UINT, xj, NB_BYTES_EQ, NB_WORD_EQ);
                    for (jq = iq + 1; jq < HFEnvq; ++jq)
                    {
                        xj = m.get(jq);
                        LOOPJR_UNROLLED_64(c, pk, 0, NB_BITS_UINT, xj, NB_BYTES_EQ, NB_WORD_EQ);
                    }
                    if (HFEnvr != 0)
                    {
                        choose_LOOPJR(c, pk, 0, m.get(HFEnvq), NB_BYTES_EQ, NB_WORD_EQ);
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
                    c.setXorRange(0, pk, 0, NB_WORD_EQ);
                    pk.moveNextBytes(NB_BYTES_EQ);
                    choose_LOOPJR(c, pk, ir + 1, xi >>> 1, NB_BYTES_EQ, NB_WORD_EQ);
                }
                else
                {
                    pk.moveNextBytes(i * NB_BYTES_EQ);
                }
                xi >>>= 1;
            }
        }
        if ((NB_EQ & 63) != 0)
        {
            c.setAnd(NB_WORD_EQ - 1, (1L << (NB_EQ & 63)) - 1L);
        }
    }

    private void choose_LOOPJR(Pointer c, PointerUnion pk, int START, long xj, int NB_BYTES_EQ, int NB_WORD_EQ)
    {
        if (HFEnvr < (LEN_UNROLLED_64 << 1))//gemss256, bluegemss256,magentagemss128
        {
            LOOPJR_NOCST_64(c, pk, START, HFEnvr, xj, NB_BYTES_EQ, NB_WORD_EQ);
        }
        else
        {
            LOOPJR_UNROLLED_64(c, pk, START, HFEnvr, xj, NB_BYTES_EQ, NB_WORD_EQ);
        }
    }

    private void LOOPJR_UNROLLED_64(Pointer c, PointerUnion pk64, int START, int NB_IT, long xj, int NB_BYTES_EQ, int NB_WORD_EQ)
    {
        int jr;
        for (jr = START; jr < (NB_IT - LEN_UNROLLED_64 + 1); jr += LEN_UNROLLED_64)
        {
            xj = LOOPJR_NOCST_64(c, pk64, 0, LEN_UNROLLED_64, xj, NB_BYTES_EQ, NB_WORD_EQ);
        }
        LOOPJR_NOCST_64(c, pk64, jr, NB_IT, xj, NB_BYTES_EQ, NB_WORD_EQ);
    }

    private long LOOPJR_NOCST_64(Pointer c, PointerUnion pk64, int START, int NB_IT, long xj, int NB_BYTES_EQ, int NB_WORD_EQ)
    {
        for (int jr = START; jr < NB_IT; ++jr)
        {
            if ((xj & 1L) != 0)
            {
                c.setXorRange(0, pk64, 0, NB_WORD_EQ);
            }
            pk64.moveNextBytes(NB_BYTES_EQ);
            xj >>>= 1;
        }
        return xj;
    }

    private long evalMQnocst_unrolled_no_simd_gf2(Pointer m, PointerUnion mq_orig)
    {
        long acc = 0;
        int i;
        int loop_end = 64;
        PointerUnion mq = new PointerUnion(mq_orig);
        long mj = m.get();
        for (i = 0; i < loop_end; ++i)
        {
            if (((mj >>> i) & 1L) != 0)
            {
                acc ^= mq.get(i) & mj;
            }
        }
        mq.move(64);
        for (int j = 1; j < NB_WORD_GF2nv; ++j)
        {
            loop_end = (NB_WORD_GF2nv == (j + 1) && HFEnvr != 0) ? HFEnvr : 64;
            mj = m.get(j);
            for (i = 0; i < loop_end; ++i)
            {
                if (((mj >>> i) & 1) != 0)
                {
                    acc ^= mq.getDotProduct(0, m, 0, j + 1);
                }
                mq.move(j + 1);
            }
        }
        acc = GeMSSUtils.XORBITS_UINT(acc);
        return acc;
    }

    public void signHFE_FeistelPatarin(SecureRandom random, byte[] sm8, byte[] m, int m_cp, int len, byte[] sk)
    {
        this.random = random;
        Pointer U = new Pointer(NB_WORD_GFqn);
        Pointer Hi_tab = new Pointer(SIZE_DIGEST_UINT);
        Pointer Hi1_tab = new Pointer(SIZE_DIGEST_UINT);
        Pointer Hi1 = new Pointer(Hi1_tab);
        final int HFEvr8 = HFEv & 7;
        /* Number of bytes that an element of GF(2^(n+v)) needs */
        final int NB_BYTES_GFqv = (HFEv >>> 3) + ((HFEvr8 != 0) ? 1 : 0);
        final long HFE_MASKv = GeMSSUtils.maskUINT(HFEvr);
        int i, k, index;
        long rem_char = 0;
        SecretKeyHFE sk_HFE = new SecretKeyHFE(this);
        Pointer V = new Pointer(NB_WORD_GFqv);
        Pointer[] linear_coefs = new Pointer[HFEDegI + 1];
        precSignHFE(sk_HFE, linear_coefs, sk);
        Pointer F = new Pointer(sk_HFE.F_struct.poly);
        /* Compute H1 = H(m) */
        Pointer Hi = new Pointer(Hi_tab);
        byte[] hash = new byte[Sha3BitStrength >>> 3];
        getSHA3Hash(Hi, 0, hash.length, m, m_cp, len, hash);
        /* It is to initialize S0 to 0, because Sk||Xk is stored in sm */
        Pointer sm = new Pointer(SIZE_SIGN_UNCOMPRESSED);
        Pointer DR = new Pointer(NB_WORD_GF2nv);
        PointerUnion DR_cp = new PointerUnion(DR);
        for (k = 1; k <= NB_ITE; ++k)
        {
            /* Compute xor(D_k,S_(k-1)) */
            DR.setRangeFromXor(sm, Hi, NB_WORD_GF2m);
            if (HFEmr8 != 0)//except fgemss and dualmodegs
                /* Clean the last char to compute rem_char (the last word is cleaned) */
            {
                DR.setAnd(NB_WORD_GF2m - 1, MASK_GF2m);
                /* Save the last byte because we need to erase this value by randombytes */
                rem_char = DR_cp.getByte(HFEmq8);
            }
            /* When the root finding fails, the minus and vinegars are regenerated */
            do
            {
                /* Compute Dk||Rk: add random to have n bits, without erased the m bits */
                if (HFEmr8 != 0)//except fgemss and dualmodegs
                {
                    /* Generation of Rk */
                    DR_cp.fillRandomBytes(HFEmq8, random, NB_BYTES_GFqn - NB_BYTES_GFqm + 1);
                    /* Put HFEm&7 first bits to 0 */
                    DR_cp.setAndThenXorByte(HFEmq8, -(1L << HFEmr8), rem_char);
                }
                else
                {
                    DR_cp.fillRandomBytes(NB_BYTES_GFqm, random, NB_BYTES_GFqn - NB_BYTES_GFqm);
                }
                /* To clean the last char (because of randombytes), the last word is cleaned */
                if ((HFEn & 7) != 0)//except dualmodegs256
                {
                    DR.setAnd(NB_WORD_GFqn - 1, MASK_GF2n);
                }
                /* Compute Sk||Xk = Inv_p(Dk,Rk) */
                /* Firstly: compute c * T^(-1) */
                vecMatProduct(U, DR, sk_HFE.T, FunctionParams.N);
                V.fillRandom(0, random, NB_BYTES_GFqv);
                if (HFEvr8 != 0) // except bluegemss256, cyangemss256, magentagemss192
                {
                    /* Clean the last word */
                    V.setAnd(NB_WORD_GFqv - 1, HFE_MASKv);
                }
                /* Evaluation of the constant, quadratic map with v vinegars */
                evalMQSv_unrolled_gf2(F, V, sk_HFE.F_HFEv);
                for (i = 0; i <= HFEDegI; ++i)
                {
                    vecMatProduct(Buffer_NB_WORD_GFqn, V, new Pointer(linear_coefs[i], NB_WORD_GFqn), FunctionParams.V);
                    F.setRangeFromXor(NB_WORD_GFqn * (((i * (i + 1)) >>> 1) + 1), linear_coefs[i], 0, Buffer_NB_WORD_GFqn, 0, NB_WORD_GFqn);
                }
            }
            while (chooseRootHFE_gf2nx(DR, sk_HFE.F_struct, U) == 0);
            /* Add the v bits to DR */
            DR.setXor(NB_WORD_GFqn - 1, V.get() << HFEnr);
            DR.setRangeRotate(NB_WORD_GFqn, V, 0, NB_WORD_GFqv - 1, 64 - HFEnr);
            if (NB_WORD_GFqn + NB_WORD_GFqv == NB_WORD_GF2nv)// for some 256 versions
            {
                DR.set(NB_WORD_GFqn + NB_WORD_GFqv - 1, V.get(NB_WORD_GFqv - 1) >>> (64 - HFEnr));
            }
            /* Finally: compute Sk||Xk = v * S^(-1) */
            vecMatProduct(sm, DR, sk_HFE.S, FunctionParams.NV);
            if (k != NB_ITE)
            {
                /* Store X1 in the signature */
                index = NB_WORD_GF2nv + (NB_ITE - 1 - k) * NB_WORD_GF2nvm;
                sm.copyFrom(index, sm, NB_WORD_GF2nv - NB_WORD_GF2nvm, NB_WORD_GF2nvm);
                /* To put zeros at the beginning of the first word of X1 */
                if (HFEmr != 0)
                {
                    sm.setAnd(index, ~MASK_GF2m);
                }
                /* Compute H2 = H(H1) */
                byte[] Hi_bytes = Hi.toBytes(SIZE_DIGEST);
                getSHA3Hash(Hi1, 0, SIZE_DIGEST, Hi_bytes, 0, Hi_bytes.length, Hi_bytes);
                /* Permutation of pointers */
                Hi1.swap(Hi);
            }
        }
        if (NB_ITE == 1)
        {
            /* Take the (n+v) first bits */
            byte[] sm64 = sm.toBytes(sm.getLength() << 3);
            System.arraycopy(sm64, 0, sm8, 0, NB_BYTES_GFqnv);
        }
        else
        {
            compress_signHFE(sm8, sm);
        }
    }

    /* Precomputation for one secret-key */
    private void precSignHFE(SecretKeyHFE sk_HFE, Pointer[] linear_coefs, byte[] sk)
    {
        Pointer F_cp;
        int i, j;
        precSignHFESeed(sk_HFE, sk);
        initListDifferences_gf2nx(sk_HFE.F_struct.L);
        Pointer F_HFEv = new Pointer(sk_HFE.F_HFEv);
        final int NB_UINT_HFEPOLY = NB_COEFS_HFEPOLY * NB_WORD_GFqn;
        Pointer F = new Pointer(NB_UINT_HFEPOLY);
        /* X^(2^0) */
        linear_coefs[0] = new Pointer(F_HFEv, MQv_GFqn_SIZE);
        /* X^(2^1) */
        F_HFEv.changeIndex(linear_coefs[0], MLv_GFqn_SIZE);
        F_cp = new Pointer(F, 2 * NB_WORD_GFqn);
        for (i = 0; i < HFEDegI; ++i)
        {
            /* Copy i quadratic terms */
            j = i - (((((1 << i) + 1) > HFE_odd_degree) && ENABLED_REMOVE_ODD_DEGREE) ? 1 : 0);
            F_cp.copyFrom(F_HFEv, j * NB_WORD_GFqn);
            F_HFEv.move(j * NB_WORD_GFqn);
            F_cp.move(j * NB_WORD_GFqn);
            /* Store the address of X^(2^(i+1)) */
            linear_coefs[i + 1] = new Pointer(F_HFEv);
            /* Linear term is not copied */
            F_HFEv.move(MLv_GFqn_SIZE);
            F_cp.move(NB_WORD_GFqn);
        }
        if (HFEDegJ != 0) //fgemss192 and fgemss256
        {
            /* X^(2^HFEDegI + 2^j) */
            j = (((1 << i) + 1) <= HFE_odd_degree) ? 0 : 1;
            F_cp.copyFrom(F_HFEv, (HFEDegJ - j) * NB_WORD_GFqn);
        }
        sk_HFE.F_struct.poly = new Pointer(F);
    }

    private void precSignHFESeed(SecretKeyHFE sk_HFE, byte[] sk)
    {
        Pointer L, U;
        int length_tmp = NB_UINT_HFEVPOLY + ((LTRIANGULAR_NV_SIZE + LTRIANGULAR_N_SIZE) << 1);
        sk_HFE.sk_uncomp = new Pointer(length_tmp + MATRIXnv_SIZE + MATRIXn_SIZE);
        SHAKEDigest shakeDigest = new SHAKEDigest(ShakeBitStrength);
        shakeDigest.update(sk, 0, SIZE_SEED_SK);
        byte[] sk_uncomp_byte = new byte[(length_tmp) << 3];
        shakeDigest.doFinal(sk_uncomp_byte, 0, sk_uncomp_byte.length);
        sk_HFE.sk_uncomp.fill(0, sk_uncomp_byte, 0, sk_uncomp_byte.length);
        sk_HFE.S = new Pointer(sk_HFE.sk_uncomp, length_tmp);
        sk_HFE.T = new Pointer(sk_HFE.S, MATRIXnv_SIZE);
        /* zero padding for the HFEv polynomial F */
        sk_HFE.F_HFEv = new Pointer(sk_HFE.sk_uncomp);
        cleanMonicHFEv_gf2nx(sk_HFE.F_HFEv);
        /* The random bytes are already generated from a seed */
        L = new Pointer(sk_HFE.sk_uncomp, NB_UINT_HFEVPOLY);
        U = new Pointer(L, LTRIANGULAR_NV_SIZE);
        cleanLowerMatrix(L, FunctionParams.NV);
        cleanLowerMatrix(U, FunctionParams.NV);
        /* Generate S^(-1) = L*U */
        mulMatricesLU_gf2(sk_HFE.S, L, U, FunctionParams.NV);
        /* The random bytes are already generated from a seed */
        L.move(LTRIANGULAR_NV_SIZE << 1);
        U.changeIndex(L, LTRIANGULAR_N_SIZE);
        cleanLowerMatrix(L, FunctionParams.N);
        cleanLowerMatrix(U, FunctionParams.N);
        /* Generate T^(-1) = L*U */
        mulMatricesLU_gf2(sk_HFE.T, L, U, FunctionParams.N);
    }

    void cleanMonicHFEv_gf2nx(Pointer F)
    {
        /* zero padding for the last word of each element of GF(2^n) */
        for (int F_idx = NB_WORD_GFqn - 1; F_idx < NB_UINT_HFEVPOLY; F_idx += NB_WORD_GFqn)
        {
            F.setAnd(F_idx, MASK_GF2n);
        }
    }

    private void mulMatricesLU_gf2(Pointer S, Pointer L, Pointer U, FunctionParams functionParams)
    {
        final int nq, nr;
        int iq;
        boolean REM;
        int S_orig = S.getIndex();
        switch (functionParams)
        {
        case N:
            nq = HFEnq;
            nr = HFEnr;
            REM = true;
            break;
        case NV:
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
        S.changeIndex(S_orig);
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
        S.set(0L);
        long tmp;
        for (int jr = 0; jr < NB_IT; ++jr)
        {
            /* Dot product */
            tmp = L.getDotProduct(0, U, 0, mini);
            tmp = GeMSSUtils.XORBITS_UINT(tmp);
            S.setXor(tmp << jr);
            U.move(jq);
        }
        S.moveIncremental();
    }

    private int setArrayL(int[] L, int k, int pos, int len)
    {
        for (int j = pos; j < len; ++j)
        {
            L[k++] = NB_WORD_GFqn << j;
        }
        return k;
    }

    private void initListDifferences_gf2nx(int[] L)
    {
        int i, k = 2;
        L[1] = NB_WORD_GFqn;
        for (i = 0; i < HFEDegI; ++i)
        {
            if (ENABLED_REMOVE_ODD_DEGREE && ((1 << i) + 1) > HFE_odd_degree)
            {
                /* j=0 */
                if (i != 0)
                {
                    L[k++] = NB_WORD_GFqn << 1;
                }
                /* j=1 to j=i */
                k = setArrayL(L, k, 1, i);
            }
            else
            {
                /* j=0 */
                L[k++] = NB_WORD_GFqn;
                /* j=1 to j=i */
                k = setArrayL(L, k, 0, i);
            }
        }
        if (HFEDegJ != 0)
        {
            if (ENABLED_REMOVE_ODD_DEGREE && ((1 << i) + 1) > HFE_odd_degree)
            {
                /* j=0 */
                L[k++] = NB_WORD_GFqn << 1;
                /* j=1 to j=i */
                setArrayL(L, k, 1, HFEDegJ - 1);
            }
            else
            {
                /* j=0*/
                L[k++] = NB_WORD_GFqn;
                setArrayL(L, k, 0, HFEDegJ - 1);
            }
        }
    }

    void evalMQSv_unrolled_gf2(Pointer c, Pointer m, Pointer pk)
    {
        Pointer x = new Pointer(HFEv);
        final int NB_VARq = HFEv >>> 6;
        final int NB_VARr = HFEv & 63;
        final int NB_WORD_EQ = (HFEn >>> 6) + ((HFEn & 63) != 0 ? 1 : 0);
        int pk_orig = pk.getIndex();
        Pointer tmp = new Pointer(NB_WORD_EQ);
        int i, j, k;
        /* Compute one time all -((xi>>1)&UINT_1) */
        for (i = 0, k = 0; i < NB_VARq; ++i)
        {
            k = x.setRange_xi(m.get(i), k, NB_BITS_UINT);
        }
        if (NB_VARr != 0)
        {
            x.setRange_xi(m.get(i), k, NB_VARr);
        }
        /* Constant cst_pk */
        c.copyFrom(pk, NB_WORD_EQ);
        pk.move(NB_WORD_EQ);
        /* for each row of the quadratic matrix of pk, excepted the last block */
        for (i = 0; i < HFEv; ++i)
        {
            /* for each column of the quadratic matrix of pk */
            /* xj=xi */
            tmp.copyFrom(pk, NB_WORD_EQ);
            pk.move(NB_WORD_EQ);
            for (j = i + 1; j < HFEv - 3; j += 4)
            {
                tmp.setXorRangeAndMaskMove(pk, NB_WORD_EQ, x.get(j));
                tmp.setXorRangeAndMaskMove(pk, NB_WORD_EQ, x.get(j + 1));
                tmp.setXorRangeAndMaskMove(pk, NB_WORD_EQ, x.get(j + 2));
                tmp.setXorRangeAndMaskMove(pk, NB_WORD_EQ, x.get(j + 3));
            }
            for (; j < HFEv; ++j)
            {
                tmp.setXorRangeAndMaskMove(pk, NB_WORD_EQ, x.get(j));
            }
            /* Multiply by xi */
            c.setXorRangeAndMask(tmp, NB_WORD_EQ, x.get(i));
        }
        pk.changeIndex(pk_orig);
    }

    private int chooseRootHFE_gf2nx(Pointer root, SecretKeyHFE.complete_sparse_monic_gf2nx F, Pointer U)
    {
        Pointer hash = new Pointer(SIZE_DIGEST_UINT);
        Pointer poly = new Pointer(((HFEDeg << 1) - 1) * NB_WORD_GFqn);
        Pointer poly2 = new Pointer((HFEDeg + 1) * NB_WORD_GFqn);
        Pointer cst = new Pointer(NB_WORD_GFqn);
        /* Constant term of F-U */
        cst.setRangeFromXor(F.poly, U, NB_WORD_GFqn);
        /* X^(2^n) - X mod (F-U) */
        if (HFEDeg <= 34 || (HFEn > 196 && HFEDeg < 256))
        {
            //HFEDeg<=34: redgemss128, redgemss192, redgemss256, magentagemss128, magentagemss192, magentagemss256
            //HFEn>196: bluegemss192, bluegemss256, cyangemss192, cyangemss256, fgemss128, dualmodems128, dualmodems192,
            // dualmodems256
            frobeniusMap_multisqr_HFE_gf2nx(poly, F, cst);
        }
        else //gemss128, gemss192, gemss256, whitegemss128, whitegemss192, whitegemss256, fgemss192, fgemss256, bluegemss128, cyangemss128
        {
            /* For i=HFEDegI, we have X^(2^i) mod (F-U) = X^(2^i). The first term of degree >= HFEDeg is X^(2^(HFEDegI+1)):
            2^(HFEDegI+1) >= HFEDeg but 2^HFEDegI < HFEDeg. So, we begin at the step i=HFEDegI+1 */
            /* Compute X^(2^(HFEDegI+1)) mod (F-U) */
            /* Step 1: compute X^(2^(HFEDegI+1)) */
            int i = 2 << HFEDegI;
            /* Xqn is initialized to 0 with calloc, so the multiprecision word is initialized to 1 just by setting the first word */
            poly.set(i * NB_WORD_GFqn, 1L);
            /* Step 2: reduction of X^(2^(HFEDegI+1)) modulo (F-U) */
            divsqr_r_HFE_cstdeg_gf2nx(poly, i, i, HFEDeg, F, cst);
            for_sqr_divsqr(poly, HFEDegI + 1, HFEn, F, cst);
        }
        /* (X^(2^n) mod (F-U)) - X */
        poly.setXor(NB_WORD_GFqn, 1L);
        /* Initialize to F */
        int l = poly2.getIndex();
        /* i=0: constant of F */
        poly2.copyFrom(F.poly, NB_WORD_GFqn);
        for_copy_move(poly2, F);
        poly2.changeIndex(l);
        /* Leading term: 1 */
        poly2.set(HFEDeg * NB_WORD_GFqn, 1L);
        /* Initialize to F-U */
        poly2.setXorRange(U, NB_WORD_GFqn);
        l = poly.getD_for_not0_or_plus(NB_WORD_GFqn, HFEDeg - 1);
        /* GCD(F-U, X^(2^n)-X mod (F-U)) */
        l = gcd_gf2nx(poly2, HFEDeg, poly, l);
        if (buffer != 0) //buffer is the result from gcd_gf2nx, it's the flag to swap
        {
            poly.swap(poly2);
        }
        if (poly.is0_gf2n(0, NB_WORD_GFqn) == 0)
        {
            /* The gcd is a constant (!=0) */
            /* Irreducible: 0 root */
            /* l=0; */
            return 0;
        }
        /* poly2 is the gcd */
        /* Here, it becomes monic */
        convMonic_gf2nx(poly2, l);
        Pointer roots = new Pointer(l * NB_WORD_GFqn);
        findRootsSplit_gf2nx(roots, poly2, l);
        if (l == 1)
        {
            /* One root */
            root.copyFrom(roots, NB_WORD_GFqn);
        }
        else
        {
            /* Sort the roots */
            fast_sort_gf2n(roots, l);
            /* Choose a root with a determinist hash */
            getSHA3Hash(hash, 0, Sha3BitStrength >>> 3, U.toBytes(NB_BYTES_GFqn), 0,
                NB_BYTES_GFqn, new byte[Sha3BitStrength >>> 3]);
            root.copyFrom(0, roots, (int)remainderUnsigned(hash.get(), l) * NB_WORD_GFqn, NB_WORD_GFqn);
        }
        return l;
    }

    private int gcd_gf2nx(Pointer A, int da, Pointer B, int db)
    {
        Pointer inv = new Pointer(NB_WORD_GFqn);
        Pointer tmp;
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
                for_mul(B, inv, db - 1);
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

    private void for_mul(Pointer res_orig, Pointer inv, int start)
    {
        Pointer res = new Pointer(res_orig, start * NB_WORD_GFqn);
        for (int i = start; i != -1; --i)
        {
            mul_gf2n(res, res, inv);
            res.move(-NB_WORD_GFqn);
        }
    }

    /**
     * @return The degree of Xqn.
     * @brief Computation of (X^(2^n) - X) mod (F-U).
     * @param[out] Xqn Xqn = (X^(2^n) - X) mod (F.poly-U) in GF(2^n)[X].
     * @param[in] F   A HFE polynomial in GF(2^n)[X] stored with a sparse rep.
     * @param[in] U   An element of GF(2^n).
     * @remark Requires to allocate (2*HFEDeg-1)*NB_WORD_GFqn words for Xqn.
     * @remark Requirement: F is monic.
     * @remark Requirement: F.L must be initialized with initListDifferences_gf2nx.
     * @remark Constant-time implementation.
     */
    private void frobeniusMap_multisqr_HFE_gf2nx(Pointer Xqn, SecretKeyHFE.complete_sparse_monic_gf2nx F, Pointer cst)
    {
        Pointer Xqn_cp = new Pointer();
        Pointer Xqn_sqr = new Pointer(HFEDeg * NB_WORD_GFqn);
        Pointer current_coef = new Pointer();
        int i, j, k;
        /* Table of the X^(k*2^II) mod F. */
        Pointer table = new Pointer((KX * HFEDeg + POW_II) * NB_WORD_GFqn);
        /* j=POW_II*KP-D, we reduce X^(D+j) mod F. */
        j = POW_II * KP - HFEDeg;
        /* i=0: constant of F */
        Pointer table_cp = new Pointer(table, NB_WORD_GFqn * j);
        table_cp.copyFrom(cst, NB_WORD_GFqn);
        for_copy_move(table_cp, F);
        /* Second step: we compute X^(KP*(2^II)-D)*(F - X^D) mod F */
        /* We reduce one by one the coefficients leading_coef*X^(D+j) mod F,
       by using X^(D+j) = X^j * X^D = X^j * (F-X^D) mod F. */
        divsqr_r_HFE_cstdeg_gf2nx(table, j - 1 + HFEDeg, j - 1, 0, F, cst);
        /* Computation of the other elements of the table: X^(k*(2^II)) mod F.
        X^(k*(2^II)) = (X^((k-1)*(2^II)) mod F) * X^(2^II) mod F. */
        for (k = KP + 1; k < HFEDeg; ++k)
        {
            /* Update the current polynomial */
            table_cp.changeIndex(table, HFEDeg * NB_WORD_GFqn);
            /* Multiplication of (X^((k-1)*(2^II)) mod F) by X^(2^II) */
            table_cp.setRangeClear(0, POW_II * NB_WORD_GFqn);
            table_cp.copyFrom(POW_II * NB_WORD_GFqn, table, 0, HFEDeg * NB_WORD_GFqn);
            /* Update the current polynomial */
            table.changeIndex(table_cp);
            /* Reduction of (X^((k-1)*(2^II)) mod F) * X^(2^II) modulo F */
            /* We reduce one by one the coefficients leading_coef*X^(D+j) mod F,
           by using X^(D+j) = X^j * X^D = X^j * (F-X^D) mod F. */
            divsqr_r_HFE_cstdeg_gf2nx(table, POW_II - 1 + HFEDeg, POW_II - 1, 0, F, cst);
        }
        table.indexReset();
        /* X^(2^(HFEDegI+II)) = X^( (2^HFEDegI) * (2^II)) */
        /* We take the polynomial from the table */
        Xqn.copyFrom(0, table, (((1 << HFEDegI) - KP) * HFEDeg) * NB_WORD_GFqn, HFEDeg * NB_WORD_GFqn);
        for (i = 0; i < ((HFEn - HFEDegI - II) / II); ++i)
        {
            /* Step 1: Xqn^(2^II) with II squarings */
            /* Xqn_sqr is the list of the coefficients of Xqn at the power 2^II */
            /* j=0, first squaring */
            loop_sqr(Xqn_sqr, Xqn);
            /* The other squarings */
            for (j = 1; j < II; ++j)
            {
                loop_sqr(Xqn_sqr, Xqn_sqr);
            }
            /* Step 2: Reduction of Xqn^(2^II) modulo F, by using the table. Multiplication of ((X^(k*2^II)) mod F) by
            the current coefficient. */
            /* j=KP, initialization of the new Xqn */
            current_coef.changeIndex(Xqn_sqr, KP * NB_WORD_GFqn);
            table_cp.changeIndex(table);
            Xqn_cp.changeIndex(Xqn);
            for (k = 0; k < HFEDeg; ++k)
            {
                mul_gf2n(Xqn_cp, table_cp, current_coef);
                Xqn_cp.move(NB_WORD_GFqn);
                table_cp.move(NB_WORD_GFqn);
            }
            for (j = KP + 1; j < HFEDeg; ++j)
            {
                current_coef.move(NB_WORD_GFqn);
                Xqn_cp.changeIndex(Xqn);
                for (k = 0; k < HFEDeg; ++k)
                {
                    mul_rem_xorrange(Xqn_cp, table_cp, current_coef);
                    Xqn_cp.move(NB_WORD_GFqn);
                    table_cp.move(NB_WORD_GFqn);
                }
            }
            /* The coefficients such as X^(k*2^II) mod F = X^(k*2^II). */
            for (j = 0; j < KP; ++j)
            {
                /* (X^j)^II */
                Xqn.setXorRange(j * POW_II * NB_WORD_GFqn, Xqn_sqr, j * NB_WORD_GFqn, NB_WORD_GFqn);
            }
        }
        for_sqr_divsqr(Xqn, 0, (HFEn - HFEDegI) % II, F, cst);
    }

    private void for_sqr_divsqr(Pointer Xqn, int start, int end, SecretKeyHFE.complete_sparse_monic_gf2nx F, Pointer cst)
    {
        for (int i = start; i < end; ++i)
        {
            /* Step 1: (X^(2^i) mod (F-U))^2 = X^(2^(i+1)) */
            sqr_gf2nx(Xqn, HFEDeg - 1);
            /* Step 2: X^(2^(i+1)) mod (F-U) */
            divsqr_r_HFE_cstdeg_gf2nx(Xqn, (HFEDeg - 1) << 1, (HFEDeg - 1) << 1, HFEDeg, F, cst);
        }
    }

    private void loop_sqr(Pointer Xqn_sqr, Pointer Xqn)
    {
        for (int k = 0; k < HFEDeg; ++k)
        {
            sqr_gf2n(Xqn_sqr, k * NB_WORD_GFqn, Xqn, k * NB_WORD_GFqn);
        }
    }

    private void for_copy_move(Pointer table, SecretKeyHFE.complete_sparse_monic_gf2nx F)
    {
        for (int i = 1, shift = NB_WORD_GFqn; i < NB_COEFS_HFEPOLY; ++i, shift += NB_WORD_GFqn)
        {
            table.move(F.L[i]);
            table.copyFrom(0, F.poly, i * NB_WORD_GFqn, NB_WORD_GFqn);
        }
    }

    private void divsqr_r_HFE_cstdeg_gf2nx(Pointer poly, int idx, int start, int end, SecretKeyHFE.complete_sparse_monic_gf2nx F, Pointer cst)
    {
        Pointer leading_coef = new Pointer(poly, idx * NB_WORD_GFqn);
        Pointer res = new Pointer();
        for (int j = start; j >= end; --j)
        {
            res.changeIndex(leading_coef, -HFEDeg * NB_WORD_GFqn);
            /* i=0: Constant of F-U */
            mul_rem_xorrange(res, leading_coef, cst);
            for (int i = 1; i < NB_COEFS_HFEPOLY; ++i)
            {
                res.move(F.L[i]);
                mul_rem_xorrange(res, leading_coef, F.poly, i * NB_WORD_GFqn);
            }
            leading_coef.move(-NB_WORD_GFqn);
        }
    }

    private void sqr_gf2nx(Pointer poly, int d)
    {
        int i = NB_WORD_GFqn * d;
        /* Pointer on the last coefficient of poly */
        int poly_orig = poly.getIndex();
        poly.move(i);
        /* A pointer on X^(2*(d-i)) */
        /* Pointer on the last coefficient of the square of poly */
        Pointer poly_2i = new Pointer(poly, i);
        /* Square of each coefficient, a_i X^i becomes a_i^2 X^(2i). Order: X^d X^(d-1) X^(d-2) ... X^(d-i) ... X^2 X^1 */
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
        poly.changeIndex(poly_orig);
    }

    int div_r_gf2nx(Pointer A, int da, Pointer B, int db)
    {
        Pointer leading_coef = new Pointer(NB_WORD_GFqn);
        Pointer inv = new Pointer(NB_WORD_GFqn);
        Pointer res = new Pointer(A);
        /* Compute the inverse of the leading term of B */
        inv_gf2n(inv, B, db * NB_WORD_GFqn);
        /* modular reduction */
        while (da >= db)
        {
            /* Search the current degree of A */
            da = A.searchDegree(da, db, NB_WORD_GFqn);
            if (da < db)
            {
                /* The computation of the remainder is finished */
                break;
            }
            res.changeIndex((da - db) * NB_WORD_GFqn);
            mul_gf2n(leading_coef, A, da * NB_WORD_GFqn, inv);
            /* i=0: Constant of B */
            for_mul_rem_xor_move(res, leading_coef, B, 0, db);
            /* The leading term becomes 0 */
            /* useless because every coefficients >= db will be never used */
            --da;
        }
        /* Here, da=db-1 */
        da = A.searchDegree(da, 1, NB_WORD_GFqn);
        /* Degree of the remainder */
        return da;
    }

    private void div_q_monic_gf2nx(Pointer A, int da, Pointer B, int db)
    {
        Pointer leading_coef = new Pointer();
        Pointer res = new Pointer();
        int i;
        /* modular reduction */
        while (da >= db)
        {
            /* Search the current degree of A */
            da = A.searchDegree(da, db, NB_WORD_GFqn);
            if (da < db)
            {
                /* The computation of the remainder is finished */
                break;
            }
            leading_coef.changeIndex(A, da * NB_WORD_GFqn);
            i = Math.max(0, (db << 1) - da);
            res.changeIndex(A, (da - db + i) * NB_WORD_GFqn);
            for_mul_rem_xor_move(res, leading_coef, B, i, db);
            --da;
        }
    }

    private int div_r_monic_gf2nx(Pointer A, int da, Pointer B, int db)
    {
        Pointer leading_coef = new Pointer();
        Pointer res = new Pointer();
        /* modular reduction */
        while (da >= db)
        {
            /* Search the current degree of A */
            da = A.searchDegree(da, db, NB_WORD_GFqn);
            if (da < db)
            {
                /* The computation of the remainder is finished */
                break;
            }
            leading_coef.changeIndex(A, da * NB_WORD_GFqn);
            res.changeIndex(leading_coef, -db * NB_WORD_GFqn);
            for_mul_rem_xor_move(res, leading_coef, B, 0, db);
            /* The leading term of A is a term of the quotient */
            --da;
        }
        if (da == -1)
        {
            ++da;
        }
        /* Here, da=db-1 */
        da = A.searchDegree(da, 1, NB_WORD_GFqn);
        /* Degree of the remainder */
        return da;
    }

    private void for_mul_rem_xor_move(Pointer res, Pointer leading_coef, Pointer B, int start, int end)
    {
        for (int i = start, shift = start * NB_WORD_GFqn; i < end; ++i, shift += NB_WORD_GFqn)
        {
            mul_rem_xorrange(res, leading_coef, B, shift);
            res.move(NB_WORD_GFqn);
        }
    }

    private void inv_gf2n(Pointer res, Pointer A, int AOff)
    {
        int A_orig = A.getIndex();
        A.move(AOff);
        Pointer multi_sqr = new Pointer(NB_WORD_GFqn);
        int nb_sqr, i, j;
        /* i=pos */
        res.copyFrom(A, NB_WORD_GFqn);
        for (i = HFEn_1rightmost - 1; i != (-1); --i)
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
        A.changeIndex(A_orig);
    }

    private void convMonic_gf2nx(Pointer F, int d)
    {
        Pointer inv = new Pointer(NB_WORD_GFqn);
        int F_orig = F.getIndex();
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
        F.changeIndex(F_orig);
    }

    private void findRootsSplit_gf2nx(Pointer roots, Pointer f, int deg)
    {
        if (deg == 1)
        {
            /* Extract the unique root which is the constant of f */
            roots.copyFrom(f, NB_WORD_GFqn);
            return;
        }
        if ((HFEn & 1) != 0 && deg == 2)
        {
            findRootsSplit2_HT_gf2nx(roots, f);
            return;
        }
        int b, l, d;
        Pointer poly_frob = new Pointer(((deg << 1) - 1) * NB_WORD_GFqn);
        /* poly_trace is modulo f, this degree is strictly less than deg */
        Pointer poly_trace = new Pointer(deg * NB_WORD_GFqn);
        /* f_cp a copy of f */
        Pointer f_cp = new Pointer((deg + 1) * NB_WORD_GFqn);
        Pointer inv = new Pointer(NB_WORD_GFqn);
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
                poly_trace.fillRandom(NB_WORD_GFqn, random, NB_BYTES_GFqn);
                /* Clean the last word (included the zero padding) */
                poly_trace.setAnd((NB_WORD_GFqn << 1) - 1, MASK_GF2n);
            }
            while (poly_trace.is0_gf2n(NB_WORD_GFqn, NB_WORD_GFqn) != 0);
            /* copy of f because the gcd modifies f */
            f_cp.copyFrom(f, (deg + 1) * NB_WORD_GFqn);
            traceMap_gf2nx(poly_trace, poly_frob, f_cp, deg);
            /* Degree of poly_trace */
            d = poly_trace.searchDegree(deg - 1, 1, NB_WORD_GFqn);
            l = gcd_gf2nx(f_cp, deg, poly_trace, d);
            b = buffer;
        }
        while ((l == 0) || (l == deg));
        if (b != 0)
        {
            poly_trace.swap(f_cp);
        }
        /* Here, f_cp is a non-trivial divisor of degree l */
        /* f_cp is the gcd */
        /* Here, it becomes monic */
        inv_gf2n(inv, f_cp, l * NB_WORD_GFqn);
        f_cp.set1_gf2n(l * NB_WORD_GFqn, NB_WORD_GFqn);
        for_mul(f_cp, inv, l - 1);
        /* f = f_cp * Q */
        /* This function destroyes f */
        div_q_monic_gf2nx(f, deg, f_cp, l);
        /* Necessarily, the polynomial f is null here */
        /* f_cp is monic */
        /* We can apply findRootsSplit_gf2nx recursively */
        findRootsSplit_gf2nx(roots, f_cp, l);
        /* f is monic and f_cp is monic so Q is monic */
        /* We can apply findRootsSplit_gf2nx recursively */
        findRootsSplit_gf2nx(new Pointer(roots, l * NB_WORD_GFqn), new Pointer(f, l * NB_WORD_GFqn), deg - l);
    }

    void findRootsSplit2_HT_gf2nx(Pointer roots, Pointer f)
    {
        Pointer c = new Pointer(NB_WORD_GFqn);
        Pointer alpha = new Pointer(NB_WORD_GFqn);
        int f_orig = f.getIndex();
        sqr_gf2n(c, 0, f, NB_WORD_GFqn);
        inv_gf2n(roots, c, 0);
        mul_gf2n(c, f, roots);
        findRootsSplit_x2_x_c_HT_gf2nx(alpha, c);
        f.move(NB_WORD_GFqn);
        mul_gf2n(roots, alpha, f);
        roots.setRangeFromXor(NB_WORD_GFqn, roots, 0, f, 0, NB_WORD_GFqn);
        f.changeIndex(f_orig);
    }

    void findRootsSplit_x2_x_c_HT_gf2nx(Pointer root, Pointer c)
    {
        Pointer alpha = new Pointer(NB_WORD_GFqn);
        final int e = (HFEn + 1) >>> 1;
        int i, j, e2;
        /* i=pos */
        root.copyFrom(c, NB_WORD_GFqn);
        for (i = HFEn1h_rightmost, e2 = 1; i != -1; --i)
        {
            e2 <<= 1;
            /* j=0 */
            sqr_gf2n(alpha, root);
            for (j = 1; j < e2; ++j)
            {
                sqr_gf2n(alpha, alpha);
            }
            root.setXorRange(alpha, NB_WORD_GFqn);
            e2 = e >>> i;
            if ((e2 & 1) != 0)
            {
                sqr_gf2n(alpha, root);
                sqr_gf2n(root, alpha);
                root.setXorRange(c, NB_WORD_GFqn);
            }
        }
    }

    private void traceMap_gf2nx(Pointer poly_trace, Pointer poly_frob, Pointer f, int deg)
    {
        int i = 1;
        /* (2^i) < deg does not require modular reduction by f */
        for (; (1 << i) < deg; ++i)
        {
            /* poly_trace += ((rX)^(2^i)) mod f.  Here, ((rX)^(2^i)) mod f == (rX)^(2^i) since (2^i) < deg */
            sqr_gf2n(poly_trace, NB_WORD_GFqn << i, poly_trace, NB_WORD_GFqn << (i - 1));
        }
        /* Here, (rX)^(2^i) is the first time where we need modular reduction */
        if (i < HFEn)
        {
            /* poly_frob = (rX)^(2^i) = ((rX)^(2^(i-1)))^2 */
            sqr_gf2n(poly_frob, NB_WORD_GFqn << i, poly_trace, NB_WORD_GFqn << (i - 1));
            /* poly_frob = ((rX)^(2^i)) mod f */
            div_r_monic_cst_gf2nx(poly_frob, 1 << i, f, deg);
            /* poly_trace += ((rX)^(2^i)) mod f */
            poly_trace.setXorRange(poly_frob, deg * NB_WORD_GFqn);
            for (++i; i < HFEn; ++i)
            {
                /* poly_frob = (rX)^(2^i) = ((rX)^(2^(i-1)) mod f)^2 */
                sqr_gf2nx(poly_frob, deg - 1);
                /* poly_frob = ((rX)^(2^i)) mod f */
                div_r_monic_cst_gf2nx(poly_frob, (deg - 1) << 1, f, deg);
                /* poly_trace += ((rX)^(2^i)) mod f */
                poly_trace.setXorRange(poly_frob, deg * NB_WORD_GFqn);
            }
        }
    }

    private void div_r_monic_cst_gf2nx(Pointer A, int da, Pointer B, int db)
    {
        Pointer res = new Pointer();
        int A_orig = A.getIndex();
        /* Pointer on the current leading term of A */
        A.move(da * NB_WORD_GFqn);
        for (; da >= db; --da)
        {
            res.changeIndex(A, -db * NB_WORD_GFqn);
            for_mul_rem_xor_move(res, A, B, 0, db);
            /* useless because every coefficients >= db will be never used */
            A.move(-NB_WORD_GFqn);
        }
        A.changeIndex(A_orig);
    }

    /**
     * @brief Sort in ascending order of a vector in GF(2^n), in-place.
     * @details The fastest constant-time sort of this library.
     * The elements of GF(2^n) are seen as unsigned integers.
     * @param[in,out] tab A vector of l elements of GF(2^n). Will be sorted.
     * @param[in] l   The length of tab.
     * @remark Requirement: l>1.
     * @remark Constant-time implementation when l is not secret.
     */
    void fast_sort_gf2n(Pointer tab, int l)
    {
        Pointer tmp = new Pointer(NB_WORD_GFqn);
        Pointer prod = new Pointer(NB_WORD_GFqn);
        Pointer tab_i = new Pointer();
        Pointer tab_ipa = new Pointer();
        /* pow2_prev,pa,pb,pc are powers of two */
        int i, quo, rem, pow2_prev, pa, pb;
        /* The power of 2 before l, which is 1<<position(MSB(l-1)). */
        pow2_prev = GeMSSUtils.Highest_One(l - 1);
        for (pa = pow2_prev; pa > 1; pa >>>= 1)
        {
            /* Number of complete blocks */
            quo = l / (pa << 1);
            /* Size of the remainder block */
            /* Impact on the sort */
            rem = Math.max(0, l - (pa << 1) * quo - pa);
            tab_i.changeIndex(tab);
            tab_ipa.changeIndex(tab, pa * NB_WORD_GFqn);
            for (i = 0; i < quo; ++i)
            {
                for_casct_move(tab_i, tab_ipa, prod, pa, 1);
                tab_i.move(pa * NB_WORD_GFqn);
                tab_ipa.move(pa * NB_WORD_GFqn);
            }
            for_casct_move(tab_i, tab_ipa, prod, rem, 1);
            for (pb = pow2_prev, i = 0; pb > pa; pb >>>= 1)
            {
                /* l>1 implies pb<l. */
                for (; i < (l - pb); ++i)
                {
                    if ((i & pa) == 0)
                    {
                        tab_ipa.changeIndex(tab, (i + pa) * NB_WORD_GFqn);
                        copy_for_casct(tmp, tab_ipa, tab, tab_i, prod, pb, i);
                        tab_ipa.copyFrom(tmp, NB_WORD_GFqn);
                    }
                }
            }
        }
        /* pa=1 */
        tab_i.changeIndex(tab);
        tab_ipa.changeIndex(tab, NB_WORD_GFqn);
        for_casct_move(tab_i, tab_ipa, prod, l - 1, 2);
        tab_ipa.changeIndex(tab, NB_WORD_GFqn);
        for (pb = pow2_prev, i = 0; pb > 1; pb >>>= 1)
        {
            /* l>1 implies pb<l. */
            for (; i < (l - pb); i += 2)
            {
                copy_for_casct(tmp, tab_ipa, tab, tab_i, prod, pb, i);
                tab_ipa.copyFrom(tmp, NB_WORD_GFqn);
                tab_ipa.move(NB_WORD_GFqn << 1);
            }
        }
    }

    private void copy_for_casct(Pointer tmp, Pointer tab_ipa, Pointer tab, Pointer tab_i, Pointer prod, int pb, int i)
    {
        tmp.copyFrom(tab_ipa, NB_WORD_GFqn);
        for (int pc = pb; pc > 1; pc >>>= 1)
        {
            tab_i.changeIndex(tab, (i + pc) * NB_WORD_GFqn);
            CMP_AND_SWAP_CST_TIME(tmp, tab_i, prod);
        }
    }

    private void for_casct_move(Pointer tab_i, Pointer tab_ipa, Pointer prod, int len, int shift)
    {
        int move = NB_WORD_GFqn * shift;
        for (int j = 0; j < len; j += shift)
        {
            CMP_AND_SWAP_CST_TIME(tab_i, tab_ipa, prod);
            tab_i.move(move);
            tab_ipa.move(move);
        }
    }

    private void CMP_AND_SWAP_CST_TIME(Pointer tab, Pointer tab_j, Pointer prod)
    {
        long d, bo, mask;
        int i;
        /* Compute d the larger index such as a[d]!=b[d], in constant-time */
        for (i = NB_WORD_GFqn - 1, mask = 0L, d = 0L; i > 0; --i)
        {
            bo = tab_j.get(i) ^ tab.get(i);
            bo = GeMSSUtils.ORBITS_UINT(bo);
            mask |= bo;
            d += mask;
        }
        /* Return a[d]<b[d] in constant-time */
        for (i = 0, mask = 0L; i < NB_WORD_GFqn; ++i)
        {
            bo = i ^ d;
            bo = GeMSSUtils.NORBITS_UINT(bo);
            mask |= (-bo) & GeMSSUtils.CMP_LT_UINT(tab_j.get(i), tab.get(i));
        }
        prod.setRangeFromXorAndMask_xor(tab, tab_j, -mask, NB_WORD_GFqn);
    }

    public void compress_signHFE(byte[] sm8, Pointer sm)
    {
        byte[] sm64 = sm.toBytes(sm.getLength() << 3);
        /* Take the (n+v) first bits */
        System.arraycopy(sm64, 0, sm8, 0, NB_BYTES_GFqnv);
        /* Take the (Delta+v)*(nb_ite-1) bits */
        int k1, k2, nb_bits, nb_rem2, nb_rem_m, val_n, nb_rem;
        /* HFEnv bits are already stored in sm8 */
        nb_bits = HFEnv;
        int sm64_cp = (NB_WORD_GF2nv << 3) + (HFEmq8 & 7);
        for (k1 = 1; k1 < NB_ITE; ++k1)
        {
            /* Number of bits to complete the byte of sm8, in [0,7] */
            val_n = Math.min(HFEDELTA + HFEv, (8 - (nb_bits & 7)) & 7);
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
            nb_rem2 = HFEDELTA + HFEv - val_n;
            /*nb_rem2 can be zero only in this case */
            /* Number of bits used of sm64, mod 8 */
            nb_rem_m = (HFEm + val_n) & 7;
            /* Other bytes */
            if (nb_rem_m != 0)
            {
                /* -1 to take the ceil of /8, -1 */
                for (k2 = 0; k2 < ((nb_rem2 - 1) >>> 3); ++k2)
                {
                    sm8[nb_bits >>> 3] = (byte)(((sm64[sm64_cp] & 0xFF) >>> nb_rem_m) ^ ((sm64[++sm64_cp] & 0xFF) << (8 - nb_rem_m)));
                    nb_bits += 8;
                }
                /* The last byte of sm8, between 1 and 8 bits to put */
                sm8[nb_bits >>> 3] = (byte)((sm64[sm64_cp++] & 0xFF) >>> nb_rem_m);
                /* nb_rem2 between 1 and 8 bits */
                nb_rem2 = ((nb_rem2 + 7) & 7) + 1;
                if (nb_rem2 > (8 - nb_rem_m))
                {
                    sm8[nb_bits >>> 3] ^= (byte)((sm64[sm64_cp++] & 0xFF) << (8 - nb_rem_m));
                }
                nb_bits += nb_rem2;
            }
            else
            {
                /* We are at the beginning of the bytes of sm8 and sm64 */
                /* +7 to take the ceil of /8 */
                for (k2 = 0; k2 < ((nb_rem2 + 7) >>> 3); ++k2)
                {
                    sm8[nb_bits >>> 3] = sm64[sm64_cp++];
                    nb_bits += 8;
                }
                /* The last byte has AT MOST 8 bits. */
                nb_bits -= (8 - (nb_rem2 & 7)) & 7;
            }
            /* We complete the word. Then we search the first byte. */
            sm64_cp += ((8 - (NB_BYTES_GFqnv & 7)) & 7) + (HFEmq8 & 7);
        }
    }

    void convMQS_one_to_last_mr8_equations_gf2(byte[] pk_U, PointerUnion pk_cp)
    {
        int ir, jq, jr, tmp, pk_U_cp = 0;
        /* To have equivalence between *pk and pk[iq] */
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
                tmp = ((pk_cp2.getByte() >>> ir) & 1);
                pk_cp2.moveNextBytes(NB_BYTES_GFqm);
                for (jr = 1; jr < 8; ++jr)
                {
                    tmp ^= ((pk_cp2.getByte() >>> ir) & 1) << jr;
                    pk_cp2.moveNextBytes(NB_BYTES_GFqm);
                }
                pk_U[pk_U_cp++] = (byte)tmp;
            }
            if (HFENr8 != 0)
            {
                /* jr=0 */
                long tmp1 = ((pk_cp2.getWithCheck() >>> ir) & 1);
                pk_cp2.moveNextBytes(NB_BYTES_GFqm);
                for (jr = 1; jr < HFENr8; ++jr)
                {
                    tmp1 ^= ((pk_cp2.getWithCheck() >>> ir) & 1) << jr;
                    pk_cp2.moveNextBytes(NB_BYTES_GFqm);
                }
                pk_U[pk_U_cp++] = (byte)tmp1;
            }
        }
    }

    void convMQ_UL_gf2(byte[] pk, byte[] pk_U, int end)
    {
        int pk_p, pk_U_cp;
        for (int j = 0; j < end; ++j)
        {
            pk_p = ACCESS_last_equations8 + j * NB_BYTES_EQUATION;
            pk_U_cp = j * NB_BYTES_EQUATION;
            for_setPK(pk, pk_U, pk_p, pk_U_cp, HFEnv + 1);
        }
    }

    private int for_setPK(byte[] pk, byte[] pk_U, int pk_p, int pk_U_cp, int end)
    {
        int i, k;
        /* Constant + x_0*x_0 */
        pk[pk_p] = (byte)(pk_U[pk_U_cp] & 3);
        /* For each row of the output (the first is already done) */
        for (k = 2, i = 2; i < end; ++i)
        {
            k = setPK(pk, pk_U, i, pk_p, pk_U_cp, k, HFEnv - 1, HFEnv - i);
        }
        return k;
    }

    private int setPK(byte[] pk, byte[] pk_U, int nb_bits, int pk_p, int pk_U_cp, int k, int start, int end)
    {
        /* For each column */
        for (int j = start; j >= end; --j, ++k)
        {
            pk[pk_p + (k >>> 3)] ^= ((pk_U[pk_U_cp + (nb_bits >>> 3)] >>> (nb_bits & 7)) & 1) << (k & 7);
            nb_bits += j;
        }
        buffer = nb_bits;// support for convMQS_one_eq_to_hybrid_rep8_uncomp_gf2
        return k;
    }

    void convMQS_one_eq_to_hybrid_rep8_comp_gf2(byte[] pk, PointerUnion pk_cp, byte[] pk_U)
    {
        int i, pk_p = 0;
        convMQ_UL_gf2(pk, pk_U, HFEmr8);
        /* Monomial representation */
        for (i = 0; i < NB_MONOMIAL_PK; ++i)
        {
            pk_p = pk_cp.toBytesMove(pk, pk_p, HFEmq8);
            /* Jump the coefficients of the HFEmr8 last equations */
            if (HFEmr8 != 0)//gemss128
            {
                pk_cp.moveNextByte();
            }
        }
    }

    void convMQS_one_eq_to_hybrid_rep8_uncomp_gf2(byte[] pk, PointerUnion pk_cp, byte[] pk_U)
    {
        int i, j = HFEmr8 - 1, k, nb_bits;
        long val = 0;
        convMQ_UL_gf2(pk, pk_U, j);
        /* The last equation is smaller because compressed */
        int pk2_cp = ACCESS_last_equations8 + j * NB_BYTES_EQUATION;
        int pk_U_cp = j * NB_BYTES_EQUATION;
        k = for_setPK(pk, pk_U, pk2_cp, pk_U_cp, HFEnv);
        /* i == HFEnv */
        nb_bits = HFEnv;
        /* For each column */
        k = setPK(pk, pk_U, nb_bits, pk2_cp, pk_U_cp, k, HFEnv - 1, LOST_BITS);
        for (j = LOST_BITS - 1, nb_bits = buffer; j >= 0; --j, ++k)
        {
            val ^= ((long)((pk_U[pk_U_cp + (nb_bits >>> 3)] >>> (nb_bits & 7)) & 1)) << (LOST_BITS - 1 - j);
            nb_bits += j;
        }
        /* We put the last bits (stored in val) and we put it in the zero padding of each equation (excepted in
        the last since it is not complete since we use its last bits to fill the paddings) */
        pk2_cp = ACCESS_last_equations8 - 1;
        for (j = 0; j < HFEmr8 - 1; ++j)
        {
            /* Last byte of the equation */
            pk2_cp += NB_BYTES_EQUATION;
            pk[pk2_cp] ^= ((byte)(val >>> (j * HFENr8c))) << HFENr8;
        }
        /* Monomial representation */
        pk_cp.indexReset();
        for (i = 0, pk2_cp = 0; i < NB_MONOMIAL_PK; ++i)
        {
            pk2_cp = pk_cp.toBytesMove(pk, pk2_cp, HFEmq8);
            /* Jump the coefficients of the HFEmr8 last equations */
            pk_cp.moveNextByte();
        }
    }

    public int crypto_sign_open(byte[] PK, byte[] message, byte[] signature)
    {
        PointerUnion pk = new PointerUnion(PK);
        int i;
        long val = 0;
        if (HFENr8 != 0 && HFEmr8 > 1) //except gemss128, fgemss and dualmodems
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
            Pointer pk_tmp = new Pointer(1 + NB_WORD_UNCOMP_EQ * HFEmr8);
            long cst = 0;
            PointerUnion pk64 = new PointerUnion(pk);
            for (i = 0; i < HFEmr8 - 1; i++)
            {
                pk64.setByteIndex(ACCESS_last_equations8 + i * NB_BYTES_EQUATION);
                cst ^= convMQ_uncompressL_gf2(new Pointer(pk_tmp, 1 + i * NB_WORD_UNCOMP_EQ), pk64) << i;
            }
            pk64.setByteIndex(ACCESS_last_equations8 + i * NB_BYTES_EQUATION);
            /* The last equation in input is smaller because compressed */
            cst ^= convMQ_last_uncompressL_gf2(new Pointer(pk_tmp, 1 + i * NB_WORD_UNCOMP_EQ), pk64) << i;
            if (HFENr8 != 0)
            {
                /* Number of lost bits by the zero padding of each equation (without the last) */
                if (HFEnvr == 0) //redgemss128
                {
                    pk_tmp.setXor((i + 1) * NB_WORD_UNCOMP_EQ, val << (64 - LOST_BITS));
                }
                else if (HFEnvr > LOST_BITS)
                {
                    //gemss192, bluegemss128, bluegemss192, redgemss192, redgemss256, whitegemss128, whitegemss256
                    //cyangemss128, cyangemss192, cyangemss256, magentagemss192
                    pk_tmp.setXor((i + 1) * NB_WORD_UNCOMP_EQ, val << (HFEnvr - LOST_BITS));
                }
                else if (HFEnvr == LOST_BITS) //gemss256, bluegemss256
                {
                    pk_tmp.set((i + 1) * NB_WORD_UNCOMP_EQ, val);
                }
                else // whitegemss192, magentagemss128, magentagemss256
                {
                    pk_tmp.setXor((i + 1) * NB_WORD_UNCOMP_EQ - 1, val << (64 - (LOST_BITS - HFEnvr)));
                    pk_tmp.set((i + 1) * NB_WORD_UNCOMP_EQ, val >>> (LOST_BITS - HFEnvr));
                }
            }
            pk_tmp.set(cst << (HFEmr - HFEmr8));
            return sign_openHFE_huncomp_pk(message, message.length, signature, pk, new PointerUnion(pk_tmp));
        }
        else
        {
            Pointer sm = new Pointer(SIZE_SIGN_UNCOMPRESSED);
            Pointer Si_tab = new Pointer(NB_WORD_GF2nv);
            /* Copy of pointer */
            Pointer Si = new Pointer(Si_tab);
            /* Vector of D_1, ..., D_(NB_ITE) */
            Pointer D = new Pointer(SIZE_DIGEST_UINT);
            /* Take the (n+v) first bits */
            sm.fill(0, signature, 0, NB_BYTES_GFqnv);
            byte[] hashbuffer = new byte[64];
            /* Compute H1 = H(m), the m first bits are D1 */
            getSHA3Hash(D, 0, 64, message, 0, message.length, hashbuffer);
            /* Compute p(S_(NB_IT),X_(NB_IT)) */
            evalMQSnocst8_quo_gf2(Si, sm, pk);
            /* D1'' == D1 */
            return Si.isEqual_nocst_gf2(D, NB_WORD_GF2m);
        }
    }

    /**
     * @return 0 if the result is correct, ERROR_ALLOC for error from
     * malloc/calloc functions.
     * @brief Apply the change of variables x'=xS to a MQS stored with a monomial
     * representation.
     * @details MQS = (c,Q), with c the constant part in GF(2^n) and Q is an upper
     * triangular matrix of size (n+v)*(n+v) in GF(2^n). We have MQS = c + xQxt
     * with x =  (x0 x1 ... x_(n+v)). At the end of the function, we have
     * MQS = c + xQ'xt with Q' = SQSt. We multiply S by Q, then SQ by St.
     * @param[in,out] MQS A MQS in GF(2^n)[x1,...,x_(n+v)] (n equations,
     * n+v variables).
     * @param[in] S   A matrix (n+v)*(n+v) in GF(2). S should be invertible
     * (by definition of a change of variables).
     * @remark This function should be faster than changeVariablesMQS_simd_gf2
     * when SIMD is not used.
     * @remark Constant-time implementation.
     */
    void changeVariablesMQS64_gf2(Pointer MQS, Pointer S)
    {
        Pointer MQS_cpj = new Pointer();
        int iq, ir, j, jq, jr;
        /* Tmp matrix (n+v)*(n+v) of quadratic terms to compute S*Q */
        Pointer MQS2 = new Pointer(HFEnv * HFEnv * NB_WORD_GFqn);
        /* To avoid the constant of MQS */
        Pointer MQS_cpi = new Pointer(MQS, NB_WORD_GFqn);
        Pointer MQS2_cp = new Pointer(MQS2);
        Pointer S_cpj = new Pointer(S);
        /* Step 1 : compute MQS2 = S*Q */
        /* Use multiplication by transpose (so by rows of Q) */
        /* It is possible because X*Q*tX = X*tQ*tX (with X = (x1 ... xn)) */
        /* Warning : Q is a upper triangular matrix in GF(q^n) */
        /* In this code, we have : */
        /* i = iq*NB_BITS_UINT + ir */
        /* k = kq*NB_BITS_UINT + kr */
        /* *MQS_cpi = MQS[NB_WORD_GFqn] */
        /* *MQS_cpj = MQS_cpi[(((i*(2n-i+1))/2) + k)*NB_WORD_GFqn] */
        /* The previous formula is a bit complicated, so the idea is :
         *MQS_cpj would equal MQS_cpi[i][i+k] if MQS used n*n in memory */
        /* *MQS2_cp = MQS2[i*NB_WORD_GFqn] */
        /* *S_cpj = S[j*NB_WORD_GFqn+iq] */
        /* for each row j of S */
        for (j = 0; j < HFEnv; ++j)
        {
            /* initialisation at the first row of Q */
            MQS_cpj.changeIndex(MQS_cpi);
            /* for each row of Q excepted the last block */
            for (iq = 0; iq < HFEnvq; ++iq)
            {
                for (ir = 0; ir < NB_BITS_UINT; ++ir)
                {
                    /* Compute a dot product */
                    LOOPKR(MQS_cpj, MQS2_cp, S_cpj.get() >>> ir, ir, NB_BITS_UINT);
                    LOOPK_COMPLETE(MQS2_cp, S_cpj, MQS_cpj, 1, HFEnvq - iq);
                }
                /* 64 bits of zero in Q */
                S_cpj.moveIncremental();
            }
            /* the last block */
            if (HFEnvr != 0) //except dualmodems256
            {
                for (ir = 0; ir < HFEnvr; ++ir)
                {
                    /* Compute a dot product */
                    LOOPKR(MQS_cpj, MQS2_cp, S_cpj.get() >>> ir, ir, HFEnvr);
                    /* update the next element to compute */
                    MQS2_cp.move(NB_WORD_GFqn);
                }
                /* Next row of S */
                S_cpj.moveIncremental();
            }
        }
        /* Step 2 : compute MQS = MQS2*tS = (S*Q)*tS */
        /* Use multiplication by transpose (so by rows of S) */
        /* Permute MQS and MQS2 */
        MQS_cpi.changeIndex(MQS2);
        MQS2_cp.changeIndex(MQS, NB_WORD_GFqn);
        Pointer S_cpi = new Pointer(S);
        /* First : compute upper triangular result */
        /* In this code, we have : */
        /* *MQS_cpi = MQS2[j*n*NB_WORD_GFqn] */
        /* *MQS_cpj = MQS2[(j*n+k)*NB_WORD_GFqn] */
        /* *MQS2_cp = MQS[(((j*(2n-j+1))/2) + i-j)*NB_WORD_GFqn] */
        /* The previous formula is a bit complicated, so the idea is :
         *MQS2_cp would equal MQS[j][i] if MQS used n*n in memory */
        /* *S_cpi = S[j*NB_WORD_GFqn] */
        /* *S_cpj = S[i*NB_WORD_GFqn] */
        /* for each row j of MQS2 excepted the last block */
        for (jq = 0; jq < HFEnvq; ++jq)
        {
            for (jr = 0; jr < NB_BITS_UINT; ++jr)
            {
                S_cpj.changeIndex(S_cpi);
                /* for each row >=j of S */
                LOOPIR_INIT(MQS2_cp, MQS_cpj, MQS_cpi, S_cpj, jr, NB_BITS_UINT);
                for (iq = jq + 1; iq < HFEnvq; ++iq)
                {
                    LOOPIR_INIT(MQS2_cp, MQS_cpj, MQS_cpi, S_cpj, 0, NB_BITS_UINT);
                }
                /* the last block */
                if (HFEnvr != 0)//except dualmodems256
                {
                    LOOPIR_INIT(MQS2_cp, MQS_cpj, MQS_cpi, S_cpj, 0, HFEnvr);
                }
                /* Next row of MQS2 */
                MQS_cpi.changeIndex(MQS_cpj);
                /* Next row of S because of upper triangular */
                S_cpi.move(NB_WORD_GF2nv);
            }
        }
        /* the last block */
        if (HFEnvr != 0)//except dualmodems256
        {
            for (jr = 0; jr < HFEnvr; ++jr)
            {
                S_cpj.changeIndex(S_cpi);
                MQS_cpj.changeIndex(MQS_cpi);
                /* for each row >=j of S, the last block */
                LOOPIR_INIT(MQS2_cp, MQS_cpj, MQS_cpi, S_cpj, jr, HFEnvr);
                MQS_cpi.changeIndex(MQS_cpj);
                S_cpi.move(NB_WORD_GF2nv);
            }
        }
        /* Second : compute lower triangular result */
        MQS_cpi.changeIndex(MQS2);
        MQS2_cp.changeIndex(MQS, NB_WORD_GFqn);
        S_cpj.changeIndex(S);
        /* In this code, we have : */
        /* *MQS_cpi = MQS2[(j+1)*n*NB_WORD_GFqn] */
        /* *MQS_cpj = MQS2[(j+1)*n+k)*NB_WORD_GFqn] */
        /* *MQS2_cp = MQS[(((j*(2n-j+1))/2) + i-j)*NB_WORD_GFqn] */
        /* The previous formula is a bit complicated, so the idea is :
         *MQS2_cp would equal MQS[j][i] if MQS used n*n in memory */
        /* *S_cpj = S[j*NB_WORD_GFqn] */
        /* for each row j of S excepted the last block */
        for (jq = 0; jq < HFEnvq; ++jq)
        {
            for (jr = 0; jr < NB_BITS_UINT; ++jr)
            {
                /* i=j : the diagonal is already computing */
                MQS2_cp.move(NB_WORD_GFqn);
                /* The line j of MQS2 is useless */
                MQS_cpi.move(HFEnv * NB_WORD_GFqn);
                MQS_cpj.changeIndex(MQS_cpi);
                /* for each row >j of MQS2 */
                LOOPIR_LOOPK_COMPLETE(MQS2_cp, S_cpj, MQS_cpj, jr + 1, NB_BITS_UINT);
                for (iq = jq + 1; iq < HFEnvq; ++iq)
                {
                    LOOPIR_LOOPK_COMPLETE(MQS2_cp, S_cpj, MQS_cpj, 0, NB_BITS_UINT);
                }
                /* the last block */
                if (HFEnvr != 0)//except dualmodems256
                {
                    LOOPIR_LOOPK_COMPLETE(MQS2_cp, S_cpj, MQS_cpj, 0, HFEnvr);
                }
                /* Next row of S */
                S_cpj.move(NB_WORD_GF2nv);
            }
        }
        /* the last block excepted the last row */
        if (HFEnvr != 0)//except dualmodems256
        {
            for (jr = 0; jr < HFEnvr - 1; ++jr)
            {
                /* i=j : the diagonal is already computing */
                MQS2_cp.move(NB_WORD_GFqn);
                /* The line j of MQS2 is useless */
                MQS_cpi.move(HFEnv * NB_WORD_GFqn);
                MQS_cpj.changeIndex(MQS_cpi);
                /* for each row >=j of S */
                /* the last block */
                LOOPIR_LOOPK_COMPLETE(MQS2_cp, S_cpj, MQS_cpj, jr + 1, HFEnvr);
                /* Next row of S */
                S_cpj.move(NB_WORD_GF2nv);
            }
        }
        MQS.indexReset();
        S.indexReset();
    }

    private void LOOPIR_INIT(Pointer MQS2_cp, Pointer MQS_cpj, Pointer MQS_cpi, Pointer S_cpj, int STARTIR, int NB_ITIR)
    {
        for (int ir = STARTIR; ir < NB_ITIR; ++ir)
        {
            MQS2_cp.setRangeClear(0, NB_WORD_GFqn);
            MQS_cpj.changeIndex(MQS_cpi);
            /* Compute a dot product */
            LOOPK_COMPLETE(MQS2_cp, S_cpj, MQS_cpj, 0, HFEnvq);
            /* update the next row of S to use */
            S_cpj.move(NB_WORD_GF2nv);
        }
    }

    private void LOOPIR_LOOPK_COMPLETE(Pointer MQS2_cp, Pointer S_cpj, Pointer MQS_cpj, int STARTIR, int NB_ITIR)
    {
        for (int ir = STARTIR; ir < NB_ITIR; ++ir)
        {
            /* Compute a dot product */
            LOOPK_COMPLETE(MQS2_cp, S_cpj, MQS_cpj, 0, HFEnvq);
        }
    }

    private void LOOPK_COMPLETE(Pointer MQS2_cp, Pointer S_cpj, Pointer MQS_cpj, int start, int end)
    {
        for (int kq = start; kq < end; ++kq)
        {
            LOOPKR(MQS_cpj, MQS2_cp, S_cpj.get(kq), 0, NB_BITS_UINT);
        }
        if (HFEnvr != 0) //except dualmodems256
        {
            LOOPKR(MQS_cpj, MQS2_cp, S_cpj.get(end), 0, HFEnvr);
        }
        /* update the next element to compute */
        MQS2_cp.move(NB_WORD_GFqn);
    }

    private void LOOPKR(Pointer MQS_cpj, Pointer MQS2_cp, long bit_kr, int START, int NB_IT)
    {
        for (int kr = START; kr < NB_IT; ++kr)
        {
            /* multiply one bit of S by one element of MQS_cpj */
            MQS2_cp.setXorRangeAndMaskMove(MQS_cpj, NB_WORD_GFqn, -(bit_kr & 1L));
            bit_kr >>>= 1;
        }
    }

    /**
     * @return 0 if the result is correct, ERROR_ALLOC for error from
     * malloc/calloc functions.
     * @brief Computation of the multivariate representation of a HFEv
     * polynomial, then a change of variables is applied.
     * @details Computation of the multivariate representation of F(XS),
     * by evaluation/interpolation. We take the following N points in GF(2)^(n+v) :
     * n0=(0 ... 0),
     * e1,e2,...,e_(n+v) with ei the i-th row of the identity matrix,
     * all ei+ej, with i<j.
     * Let p be a MQS, we have:
     * p(n0) = cst,
     * p(ei) = cst + p_i,
     * p(ei+ej) = cst + p_i + p_j + p_i,j.
     * So, these N evaluations give directly p. The interpolation is trivial.
     * @param[in] F   A monic HFEv polynomial in GF(2^n)[X,x_(n+1),...,x_(n+v)]
     * stored with a sparse representation.
     * @param[in] S   A matrix (n+v)*(n+v) in GF(2). S should be invertible
     * (by definition of a change of variables).
     * @param[out] MQS A MQS in GF(2^n)[x1,...,x_(n+v)] (n equations,
     * n+v variables). MQS is stored as one equation in GF(2^n)[x1,...,x_(n+v)]
     * (monomial representation + quadratic form cst||Q).
     * @remark Requires to allocate MQnv_GFqn_SIZE words for MQS.
     * @remark Requirement: F is monic.
     * @remark Constant-time implementation.
     */
    int interpolateHFE_FS_ref(Pointer MQS, Pointer F, Pointer S)
    {
        Pointer e_ijS = new Pointer(NB_WORD_GF2nv);
        Pointer tab_eval_i2 = new Pointer();
        Pointer e_i2S = new Pointer();
        int i, i2;
        /* Let e_i be the i-th row of the identity matrix */
        /* We compute all F(e_i*S), then all F((e_i+e_j)S) */
        /* Table of the F(e_i*S) */
        Pointer tab_eval = new Pointer(HFEnv * NB_WORD_GFqn);
        /* Constant: copy the first coefficient of F in MQS */
        MQS.copyFrom(F, NB_WORD_GFqn);
        /* e_i*S corresponds to the i-th row of S */
        Pointer e_iS = new Pointer(S);
        Pointer tab_eval_i = new Pointer(tab_eval);
        for (i = 0; i < HFEnv; ++i)
        {
            /* F(e_i*S) = cst + p_i */
            evalHFEv_gf2nx(tab_eval_i, F, e_iS);
            tab_eval_i.move(NB_WORD_GFqn);
            /* Next e_i */
            e_iS.move(NB_WORD_GF2nv);
        }
        e_iS.changeIndex(S);
        tab_eval_i.changeIndex(tab_eval);
        for (i = 0; i < HFEnv; ++i)
        {
            /* Update of MQS with F(e_i*S) from tab_eval */
            MQS.move(NB_WORD_GFqn);
            /* p_i = F(e_i*S) + cst */
            tab_eval_i.setXorRange(F, NB_WORD_GFqn);
            MQS.copyFrom(tab_eval_i, NB_WORD_GFqn);
            /* Computation of p_i,i2 by computing F((e_i+e_i2)*S) */
            tab_eval_i2.changeIndex(tab_eval_i);
            e_i2S.changeIndex(e_iS);
            for (i2 = i + 1; i2 < HFEnv; ++i2)
            {
                MQS.move(NB_WORD_GFqn);
                tab_eval_i2.move(NB_WORD_GFqn);
                e_i2S.move(NB_WORD_GF2nv);
                /* F((e_i+e_i2)*S) = cst + p_i + p_i2 + p_i,i2 */
                e_ijS.setRangeFromXor(e_iS, e_i2S, NB_WORD_GF2nv);
                evalHFEv_gf2nx(MQS, F, e_ijS);
                /* + p_i + p_i2 + cst */
                MQS.setXorRangeXor(0, tab_eval_i, 0, tab_eval_i2, 0, NB_WORD_GFqn);
            }
            tab_eval_i.move(NB_WORD_GFqn);
            e_iS.move(NB_WORD_GF2nv);
        }
        MQS.indexReset();
        return 0;
    }

    /**
     * @brief Evaluation of F in (X,v), with F a HFEv polynomial.
     * @details Firstly, we compute X^(q^j) for j=0 to HFEDegI.
     * Then, we compute, sum_j of X^(q^j)*(Bi + sum_k=0_to_(j-1) A_j,k X^(q^k)).
     * When D is a power of two, we add X^(D/2) to the last sum_k (to obtain the
     * monic term X^D). Each sum is computed in GF(2)[x], and the modular reduction
     * is computed at the end.
     * @param[out] Fxv The evaluation of F in xv, in GF(2^n).
     * @param[in] F   A monic HFEv polynomial in GF(2^n)[X] stored with a sparse
     * representation.
     * @param[in] xv  A vector of n+v elements in GF(2).
     * @remark Requirement: F is monic.
     * @remark Constant-time implementation.
     * @remark Complexity: (#F-2) multiplications in GF(2)[x],
     * Ceil(Log_2(D))+1 modular reductions,
     * Ceil(Log_2(D))-1 squares in GF(2^n).
     * We can compare to the complexity of the Horner method:
     * (#F-2) multiplications in GF(2^n),
     * Floor(Log_2(D))-2 squares in GF(2^n).
     */
    void evalHFEv_gf2nx(Pointer Fxv, Pointer F, Pointer xv)
    {
        Pointer cur_acc = new Pointer(NB_WORD_MUL);
        Pointer acc = new Pointer(NB_WORD_MUL);
        Pointer tab_Xqj = new Pointer((HFEDegI + 1) * NB_WORD_GFqn);
        Pointer tab_Xqj_cp2 = new Pointer();
        int j, F_orig = F.getIndex();
        Pointer V = new Pointer(NB_WORD_GFqv);
        Pointer tab_Xqj_cp = new Pointer(tab_Xqj, NB_WORD_GFqn);
        /* j=0: X^(2^0) */
        tab_Xqj.copyFrom(xv, NB_WORD_GFqn);
        tab_Xqj.setAnd(NB_WORD_GFqn - 1, MASK_GF2n);
        /* Compute X^(2^j) */
        for (j = 1; j <= HFEDegI; ++j)
        {
            sqr_gf2n(tab_Xqj_cp, 0, tab_Xqj_cp, -NB_WORD_GFqn);
            tab_Xqj_cp.move(NB_WORD_GFqn);
        }
        /* Evaluation of the constant, quadratic in the vinegars */
        int endloop = (NB_WORD_GFqn + NB_WORD_GFqv) == NB_WORD_GF2nv ? NB_WORD_GFqv : NB_WORD_GFqv - 1;
        V.setRangeRotate(0, xv, NB_WORD_GFqn - 1, endloop, 64 - HFEnr);
        if (NB_WORD_GFqn + NB_WORD_GFqv != NB_WORD_GF2nv)
        {
            V.set(endloop, xv.get(NB_WORD_GFqn - 1 + endloop) >>> HFEnr);
        }
        /* Evaluation of the vinegar constant */
        evalMQSv_unrolled_gf2(cur_acc, V, F);
        F.move(MQv_GFqn_SIZE);
        /* Evaluation of the linear terms in the vinegars */
        /* + evaluation of the linear and quadratic terms in X */
        /* j=0 */
        /* Degree 1 term */
        /* Linear term */
        vmpv_xorrange_move(acc, V, F);
        tab_Xqj_cp.changeIndex(tab_Xqj);
        /* mul by X */
        mul_xorrange(cur_acc, tab_Xqj_cp, acc);
        /* X^(q^j) * (sum a_j,k X^q^k) */
        for (j = 1; j < HFEDegI; ++j)
        {
            /* Linear term */
            vmpv_xorrange_move(acc, V, F);
            acc.setRangeClear(NB_WORD_GFqn, NB_WORD_MMUL - NB_WORD_GFqn);
            /* Quadratic terms */
            tab_Xqj_cp2.changeIndex(tab_Xqj_cp);
            for_mul_xorrange_move(acc, F, tab_Xqj_cp2, j);
            rem_gf2n(acc, 0, acc);
            mul_xorrange(cur_acc, tab_Xqj_cp2, acc);
        }
        /* j=HFEDegI */
        vmpv_xorrange_move(acc, V, F);
        /* Quadratic terms */
        tab_Xqj_cp2.changeIndex(tab_Xqj_cp);
        if (HFEDegJ != 0)
        {
            acc.setRangeClear(NB_WORD_GFqn, NB_WORD_MMUL - NB_WORD_GFqn);
            for_mul_xorrange_move(acc, F, tab_Xqj_cp2, HFEDegJ);
            /* k=HFEDegJ : monic case */
            acc.setXorRange(tab_Xqj_cp2, NB_WORD_GFqn);
            rem_gf2n(acc, 0, acc);
        }
        else
        {
            /* k=HFEDegJ : monic case */
            acc.setRangeFromXor(acc, tab_Xqj_cp2, NB_WORD_GFqn);
        }
        tab_Xqj_cp.move(HFEDegI * NB_WORD_GFqn);
        mul_xorrange(cur_acc, tab_Xqj_cp, acc);
        /* Final reduction of F(xv) */
        rem_gf2n(Fxv, 0, cur_acc);
        F.changeIndex(F_orig);
    }

    private void vmpv_xorrange_move(Pointer acc, Pointer V, Pointer F)
    {
        vecMatProduct(acc, V, new Pointer(F, NB_WORD_GFqn), FunctionParams.V);
        acc.setXorRange(F, NB_WORD_GFqn);
        F.move(MLv_GFqn_SIZE);
    }

    private static long remainderUnsigned(long dividend, long divisor)
    {
        if (dividend > 0L && divisor > 0L)
        {
            return dividend % divisor;
        }
        else
        {
            return new BigInteger(1, Pack.longToBigEndian(dividend)).mod(new BigInteger(1, Pack.longToBigEndian(divisor))).longValue();
        }
    }
}