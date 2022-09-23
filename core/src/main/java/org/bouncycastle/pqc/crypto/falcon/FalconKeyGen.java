package org.bouncycastle.pqc.crypto.falcon;

class FalconKeyGen
{
    FPREngine fpr;
    FalconSmallPrimeList primes;
    FalconFFT fft;
    FalconCodec codec;
    FalconVrfy vrfy;

    FalconKeyGen()
    {
        this.fpr = new FPREngine();
        this.primes = new FalconSmallPrimeList();
        this.fft = new FalconFFT();
        this.codec = new FalconCodec();
        this.vrfy = new FalconVrfy();
    }

    private static int mkn(int logn)
    {
        return 1 << logn;
    }

    /*
     * Reduce a small signed integer modulo a small prime. The source
     * value x MUST be such that -p < x < p.
     */
    int modp_set(int x, int p)
    {
        int w;

        w = x;
        w += p & -(w >>> 31);
        return w;
    }

    /*
     * Normalize a modular integer around 0.
     */
    int modp_norm(int x, int p)
    {
        return (x - (p & (((x - ((p + 1) >>> 1)) >>> 31) - 1)));
    }

    /*
     * Compute -1/p mod 2^31. This works for all odd integers p that fit
     * on 31 bits.
     */
    int modp_ninv31(int p)
    {
        int y;

        y = 2 - p;
        y *= 2 - p * y;
        y *= 2 - p * y;
        y *= 2 - p * y;
        y *= 2 - p * y;
        return 0x7FFFFFFF & -y;
    }

    /*
     * Compute R = 2^31 mod p.
     */
    int modp_R(int p)
    {
        /*
         * Since 2^30 < p < 2^31, we know that 2^31 mod p is simply
         * 2^31 - p.
         */
        return (1 << 31) - p;
    }

    /*
     * Addition modulo p.
     */
    int modp_add(int a, int b, int p)
    {
        int d;

        d = a + b - p;
        d += p & -(d >>> 31);
        return d;
    }

    /*
     * Subtraction modulo p.
     */
    int modp_sub(int a, int b, int p)
    {
        int d;

        d = a - b;
        d += p & -(d >>> 31);
        return d;
    }

    /*
     * Montgomery multiplication modulo p. The 'p0i' value is -1/p mod 2^31.
     * It is required that p is an odd integer.
     */
    int modp_montymul(int a, int b, int p, int p0i)
    {
        long z, w;
        int d;

        z = toUnsignedLong(a) * toUnsignedLong(b);
        w = ((z * p0i) & toUnsignedLong(0x7FFFFFFF)) * p;
        d = (int)((z + w) >>> 31) - p;
        d += p & -(d >>> 31);
        return d;
    }

    /*
     * Compute R2 = 2^62 mod p.
     */
    int modp_R2(int p, int p0i)
    {
        int z;

        /*
         * Compute z = 2^31 mod p (this is the value 1 in Montgomery
         * representation), then double it with an addition.
         */
        z = modp_R(p);
        z = modp_add(z, z, p);

        /*
         * Square it five times to obtain 2^32 in Montgomery representation
         * (i.e. 2^63 mod p).
         */
        z = modp_montymul(z, z, p, p0i);
        z = modp_montymul(z, z, p, p0i);
        z = modp_montymul(z, z, p, p0i);
        z = modp_montymul(z, z, p, p0i);
        z = modp_montymul(z, z, p, p0i);

        /*
         * Halve the value mod p to get 2^62.
         */
        z = (z + (p & -(z & 1))) >>> 1;
        return z;
    }

    /*
     * Compute 2^(31*x) modulo p. This works for integers x up to 2^11.
     * p must be prime such that 2^30 < p < 2^31; p0i must be equal to
     * -1/p mod 2^31; R2 must be equal to 2^62 mod p.
     */
    int modp_Rx(int x, int p, int p0i, int R2)
    {
        int i;
        int r, z;

        /*
         * 2^(31*x) = (2^31)*(2^(31*(x-1))); i.e. we want the Montgomery
         * representation of (2^31)^e mod p, where e = x-1.
         * R2 is 2^31 in Montgomery representation.
         */
        x--;
        r = R2;
        z = modp_R(p);
        for (i = 0; (1 << i) <= x; i++)
        {
            if ((x & (1 << i)) != 0)
            {
                z = modp_montymul(z, r, p, p0i);
            }
            r = modp_montymul(r, r, p, p0i);
        }
        return z;
    }

    /*
     * Division modulo p. If the divisor (b) is 0, then 0 is returned.
     * This function computes proper results only when p is prime.
     * Parameters:
     *   a     dividend
     *   b     divisor
     *   p     odd prime modulus
     *   p0i   -1/p mod 2^31
     *   R     2^31 mod R
     */
    int modp_div(int a, int b, int p, int p0i, int R)
    {
        int z, e;
        int i;

        e = p - 2;
        z = R;
        for (i = 30; i >= 0; i--)
        {
            int z2;

            z = modp_montymul(z, z, p, p0i);
            z2 = modp_montymul(z, b, p, p0i);
            z ^= (z ^ z2) & -(int)((e >>> i) & 1);
        }

        /*
         * The loop above just assumed that b was in Montgomery
         * representation, i.e. really contained b*R; under that
         * assumption, it returns 1/b in Montgomery representation,
         * which is R/b. But we gave it b in normal representation,
         * so the loop really returned R/(b/R) = R^2/b.
         *
         * We want a/b, so we need one Montgomery multiplication with a,
         * which also remove one of the R factors, and another such
         * multiplication to remove the second R factor.
         */
        z = modp_montymul(z, 1, p, p0i);
        return modp_montymul(a, z, p, p0i);
    }

    /*
     * Bit-reversal index table.
     */
    private short REV10[] = {
        0, 512, 256, 768, 128, 640, 384, 896, 64, 576, 320, 832,
        192, 704, 448, 960, 32, 544, 288, 800, 160, 672, 416, 928,
        96, 608, 352, 864, 224, 736, 480, 992, 16, 528, 272, 784,
        144, 656, 400, 912, 80, 592, 336, 848, 208, 720, 464, 976,
        48, 560, 304, 816, 176, 688, 432, 944, 112, 624, 368, 880,
        240, 752, 496, 1008, 8, 520, 264, 776, 136, 648, 392, 904,
        72, 584, 328, 840, 200, 712, 456, 968, 40, 552, 296, 808,
        168, 680, 424, 936, 104, 616, 360, 872, 232, 744, 488, 1000,
        24, 536, 280, 792, 152, 664, 408, 920, 88, 600, 344, 856,
        216, 728, 472, 984, 56, 568, 312, 824, 184, 696, 440, 952,
        120, 632, 376, 888, 248, 760, 504, 1016, 4, 516, 260, 772,
        132, 644, 388, 900, 68, 580, 324, 836, 196, 708, 452, 964,
        36, 548, 292, 804, 164, 676, 420, 932, 100, 612, 356, 868,
        228, 740, 484, 996, 20, 532, 276, 788, 148, 660, 404, 916,
        84, 596, 340, 852, 212, 724, 468, 980, 52, 564, 308, 820,
        180, 692, 436, 948, 116, 628, 372, 884, 244, 756, 500, 1012,
        12, 524, 268, 780, 140, 652, 396, 908, 76, 588, 332, 844,
        204, 716, 460, 972, 44, 556, 300, 812, 172, 684, 428, 940,
        108, 620, 364, 876, 236, 748, 492, 1004, 28, 540, 284, 796,
        156, 668, 412, 924, 92, 604, 348, 860, 220, 732, 476, 988,
        60, 572, 316, 828, 188, 700, 444, 956, 124, 636, 380, 892,
        252, 764, 508, 1020, 2, 514, 258, 770, 130, 642, 386, 898,
        66, 578, 322, 834, 194, 706, 450, 962, 34, 546, 290, 802,
        162, 674, 418, 930, 98, 610, 354, 866, 226, 738, 482, 994,
        18, 530, 274, 786, 146, 658, 402, 914, 82, 594, 338, 850,
        210, 722, 466, 978, 50, 562, 306, 818, 178, 690, 434, 946,
        114, 626, 370, 882, 242, 754, 498, 1010, 10, 522, 266, 778,
        138, 650, 394, 906, 74, 586, 330, 842, 202, 714, 458, 970,
        42, 554, 298, 810, 170, 682, 426, 938, 106, 618, 362, 874,
        234, 746, 490, 1002, 26, 538, 282, 794, 154, 666, 410, 922,
        90, 602, 346, 858, 218, 730, 474, 986, 58, 570, 314, 826,
        186, 698, 442, 954, 122, 634, 378, 890, 250, 762, 506, 1018,
        6, 518, 262, 774, 134, 646, 390, 902, 70, 582, 326, 838,
        198, 710, 454, 966, 38, 550, 294, 806, 166, 678, 422, 934,
        102, 614, 358, 870, 230, 742, 486, 998, 22, 534, 278, 790,
        150, 662, 406, 918, 86, 598, 342, 854, 214, 726, 470, 982,
        54, 566, 310, 822, 182, 694, 438, 950, 118, 630, 374, 886,
        246, 758, 502, 1014, 14, 526, 270, 782, 142, 654, 398, 910,
        78, 590, 334, 846, 206, 718, 462, 974, 46, 558, 302, 814,
        174, 686, 430, 942, 110, 622, 366, 878, 238, 750, 494, 1006,
        30, 542, 286, 798, 158, 670, 414, 926, 94, 606, 350, 862,
        222, 734, 478, 990, 62, 574, 318, 830, 190, 702, 446, 958,
        126, 638, 382, 894, 254, 766, 510, 1022, 1, 513, 257, 769,
        129, 641, 385, 897, 65, 577, 321, 833, 193, 705, 449, 961,
        33, 545, 289, 801, 161, 673, 417, 929, 97, 609, 353, 865,
        225, 737, 481, 993, 17, 529, 273, 785, 145, 657, 401, 913,
        81, 593, 337, 849, 209, 721, 465, 977, 49, 561, 305, 817,
        177, 689, 433, 945, 113, 625, 369, 881, 241, 753, 497, 1009,
        9, 521, 265, 777, 137, 649, 393, 905, 73, 585, 329, 841,
        201, 713, 457, 969, 41, 553, 297, 809, 169, 681, 425, 937,
        105, 617, 361, 873, 233, 745, 489, 1001, 25, 537, 281, 793,
        153, 665, 409, 921, 89, 601, 345, 857, 217, 729, 473, 985,
        57, 569, 313, 825, 185, 697, 441, 953, 121, 633, 377, 889,
        249, 761, 505, 1017, 5, 517, 261, 773, 133, 645, 389, 901,
        69, 581, 325, 837, 197, 709, 453, 965, 37, 549, 293, 805,
        165, 677, 421, 933, 101, 613, 357, 869, 229, 741, 485, 997,
        21, 533, 277, 789, 149, 661, 405, 917, 85, 597, 341, 853,
        213, 725, 469, 981, 53, 565, 309, 821, 181, 693, 437, 949,
        117, 629, 373, 885, 245, 757, 501, 1013, 13, 525, 269, 781,
        141, 653, 397, 909, 77, 589, 333, 845, 205, 717, 461, 973,
        45, 557, 301, 813, 173, 685, 429, 941, 109, 621, 365, 877,
        237, 749, 493, 1005, 29, 541, 285, 797, 157, 669, 413, 925,
        93, 605, 349, 861, 221, 733, 477, 989, 61, 573, 317, 829,
        189, 701, 445, 957, 125, 637, 381, 893, 253, 765, 509, 1021,
        3, 515, 259, 771, 131, 643, 387, 899, 67, 579, 323, 835,
        195, 707, 451, 963, 35, 547, 291, 803, 163, 675, 419, 931,
        99, 611, 355, 867, 227, 739, 483, 995, 19, 531, 275, 787,
        147, 659, 403, 915, 83, 595, 339, 851, 211, 723, 467, 979,
        51, 563, 307, 819, 179, 691, 435, 947, 115, 627, 371, 883,
        243, 755, 499, 1011, 11, 523, 267, 779, 139, 651, 395, 907,
        75, 587, 331, 843, 203, 715, 459, 971, 43, 555, 299, 811,
        171, 683, 427, 939, 107, 619, 363, 875, 235, 747, 491, 1003,
        27, 539, 283, 795, 155, 667, 411, 923, 91, 603, 347, 859,
        219, 731, 475, 987, 59, 571, 315, 827, 187, 699, 443, 955,
        123, 635, 379, 891, 251, 763, 507, 1019, 7, 519, 263, 775,
        135, 647, 391, 903, 71, 583, 327, 839, 199, 711, 455, 967,
        39, 551, 295, 807, 167, 679, 423, 935, 103, 615, 359, 871,
        231, 743, 487, 999, 23, 535, 279, 791, 151, 663, 407, 919,
        87, 599, 343, 855, 215, 727, 471, 983, 55, 567, 311, 823,
        183, 695, 439, 951, 119, 631, 375, 887, 247, 759, 503, 1015,
        15, 527, 271, 783, 143, 655, 399, 911, 79, 591, 335, 847,
        207, 719, 463, 975, 47, 559, 303, 815, 175, 687, 431, 943,
        111, 623, 367, 879, 239, 751, 495, 1007, 31, 543, 287, 799,
        159, 671, 415, 927, 95, 607, 351, 863, 223, 735, 479, 991,
        63, 575, 319, 831, 191, 703, 447, 959, 127, 639, 383, 895,
        255, 767, 511, 1023
    };

    /*
     * Compute the roots for NTT and inverse NTT (binary case). Input
     * parameter g is a primitive 2048-th root of 1 modulo p (i.e. g^1024 =
     * -1 mod p). This fills gm[] and igm[] with powers of g and 1/g:
     *   gm[rev(i)] = g^i mod p
     *   igm[rev(i)] = (1/g)^i mod p
     * where rev() is the "bit reversal" function over 10 bits. It fills
     * the arrays only up to N = 2^logn values.
     *
     * The values stored in gm[] and igm[] are in Montgomery representation.
     *
     * p must be a prime such that p = 1 mod 2048.
     */
    void modp_mkgm2(int[] srcgm, int gm, int[] srcigm, int igm, int logn,
                    int g, int p, int p0i)
    {
        int u, n;
        int k;
        int ig, x1, x2, R2;

        n = mkn(logn);

        /*
         * We want g such that g^(2N) = 1 mod p, but the provided
         * generator has order 2048. We must square it a few times.
         */
        R2 = modp_R2(p, p0i);
        g = modp_montymul(g, R2, p, p0i);
        for (k = logn; k < 10; k++)
        {
            g = modp_montymul(g, g, p, p0i);
        }

        ig = modp_div(R2, g, p, p0i, modp_R(p));
        k = 10 - logn;
        x1 = x2 = modp_R(p);
        for (u = 0; u < n; u++)
        {
            int v;

            v = REV10[u << k];
            srcgm[gm + v] = x1;
            srcigm[igm + v] = x2;
            x1 = modp_montymul(x1, g, p, p0i);
            x2 = modp_montymul(x2, ig, p, p0i);
        }
    }

    /*
     * Compute the NTT over a polynomial (binary case). Polynomial elements
     * are a[0], a[stride], a[2 * stride]...
     */
    void modp_NTT2_ext(int[] srca, int a, int stride, int[] srcgm, int gm, int logn,
                       int p, int p0i)
    {
        int t, m, n;

        if (logn == 0)
        {
            return;
        }
        n = mkn(logn);
        t = n;
        for (m = 1; m < n; m <<= 1)
        {
            int ht, u, v1;

            ht = t >> 1;
            for (u = 0, v1 = 0; u < m; u++, v1 += t)
            {
                int s;
                int v;
                int r1, r2;

                s = srcgm[gm + m + u];
                r1 = a + v1 * stride;
                r2 = r1 + ht * stride;
                for (v = 0; v < ht; v++, r1 += stride, r2 += stride)
                {
                    int x, y;

                    x = srca[r1];
                    y = modp_montymul(srca[r2], s, p, p0i);
                    srca[r1] = modp_add(x, y, p);
                    srca[r2] = modp_sub(x, y, p);
                }
            }
            t = ht;
        }
    }

    /*
     * Compute the inverse NTT over a polynomial (binary case).
     */
    void modp_iNTT2_ext(int[] srca, int a, int stride, int[] srcigm, int igm, int logn,
                        int p, int p0i)
    {
        int t, m, n, k;
        int ni;
        int r;

        if (logn == 0)
        {
            return;
        }
        n = mkn(logn);
        t = 1;
        for (m = n; m > 1; m >>= 1)
        {
            int hm, dt, u, v1;

            hm = m >> 1;
            dt = t << 1;
            for (u = 0, v1 = 0; u < hm; u++, v1 += dt)
            {
                int s;
                int v;
                int r1, r2;

                s = srcigm[igm + hm + u];
                r1 = a + v1 * stride;
                r2 = r1 + t * stride;
                for (v = 0; v < t; v++, r1 += stride, r2 += stride)
                {
                    int x, y;

                    x = srca[r1];
                    y = srca[r2];
                    srca[r1] = modp_add(x, y, p);
                    srca[r2] = modp_montymul(
                        modp_sub(x, y, p), s, p, p0i);
                    ;
                }
            }
            t = dt;
        }

        /*
         * We need 1/n in Montgomery representation, i.e. R/n. Since
         * 1 <= logn <= 10, R/n is an integer; morever, R/n <= 2^30 < p,
         * thus a simple shift will do.
         */
        ni = 1 << (31 - logn);
        for (k = 0, r = a; k < n; k++, r += stride)
        {
            srca[r] = modp_montymul(srca[r], ni, p, p0i);
        }
    }

    /*
     * Simplified macros for NTT and iNTT (binary case) when the elements
     * are consecutive in RAM.
     */
//    #define modp_NTT2(a, gm, logn, p, p0i)   modp_NTT2_ext(a, 1, gm, logn, p, p0i)
    void modp_NTT2(int[] srca, int a, int[] srcgm, int gm, int logn, int p, int p0i)
    {
        modp_NTT2_ext(srca, a, 1, srcgm, gm, logn, p, p0i);
    }

    //    #define modp_iNTT2(a, igm, logn, p, p0i) modp_iNTT2_ext(a, 1, igm, logn, p, p0i)
    void modp_iNTT2(int[] srca, int a, int[] srcigm, int igm, int logn, int p, int p0i)
    {
        modp_iNTT2_ext(srca, a, 1, srcigm, igm, logn, p, p0i);
    }

    /*
     * Given polynomial f in NTT representation modulo p, compute f' of degree
     * less than N/2 such that f' = f0^2 - X*f1^2, where f0 and f1 are
     * polynomials of degree less than N/2 such that f = f0(X^2) + X*f1(X^2).
     *
     * The new polynomial is written "in place" over the first N/2 elements
     * of f.
     *
     * If applied logn times successively on a given polynomial, the resulting
     * degree-0 polynomial is the resultant of f and X^N+1 modulo p.
     *
     * This function applies only to the binary case; it is invoked from
     * solve_NTRU_binary_depth1().
     */
    void modp_poly_rec_res(int[] srcf, int f, int logn,
                           int p, int p0i, int R2)
    {
        int hn, u;

        hn = 1 << (logn - 1);
        for (u = 0; u < hn; u++)
        {
            int w0, w1;

            w0 = srcf[f + (u << 1) + 0];
            w1 = srcf[f + (u << 1) + 1];
            srcf[f + u] = modp_montymul(modp_montymul(w0, w1, p, p0i), R2, p, p0i);
        }
    }

    /* ==================================================================== */
    /*
     * Custom bignum implementation.
     *
     * This is a very reduced set of functionalities. We need to do the
     * following operations:
     *
     *  - Rebuild the resultant and the polynomial coefficients from their
     *    values modulo small primes (of length 31 bits each).
     *
     *  - Compute an extended GCD between the two computed resultants.
     *
     *  - Extract top bits and add scaled values during the successive steps
     *    of Babai rounding.
     *
     * When rebuilding values using CRT, we must also recompute the product
     * of the small prime factors. We always do it one small factor at a
     * time, so the "complicated" operations can be done modulo the small
     * prime with the modp_* functions. CRT coefficients (inverses) are
     * precomputed.
     *
     * All values are positive until the last step: when the polynomial
     * coefficients have been rebuilt, we normalize them around 0. But then,
     * only additions and subtractions on the upper few bits are needed
     * afterwards.
     *
     * We keep big integers as arrays of 31-bit words (in uint32_t values);
     * the top bit of each uint32_t is kept equal to 0. Using 31-bit words
     * makes it easier to keep track of carries. When negative values are
     * used, two's complement is used.
     */

    /*
     * Subtract integer b from integer a. Both integers are supposed to have
     * the same size. The carry (0 or 1) is returned. Source arrays a and b
     * MUST be distinct.
     *
     * The operation is performed as described above if ctr = 1. If
     * ctl = 0, the value a[] is unmodified, but all memory accesses are
     * still performed, and the carry is computed and returned.
     */
    int zint_sub(int[] srca, int a, int[] srcb, int b, int len,
                 int ctl)
    {
        int u;
        int cc, m;

        cc = 0;
        m = -ctl;
        for (u = 0; u < len; u++)
        {
            int aw, w;

            aw = srca[a + u];
            w = aw - srcb[b + u] - cc;
            cc = w >>> 31;
            aw ^= ((w & 0x7FFFFFFF) ^ aw) & m;
            srca[a + u] = aw;
        }
        return cc;
    }

    /*
     * Mutiply the provided big integer m with a small value x.
     * This function assumes that x < 2^31. The carry word is returned.
     */
    int zint_mul_small(int[] srcm, int m, int mlen, int x)
    {
        int u;
        int cc;

        cc = 0;
        for (u = 0; u < mlen; u++)
        {
            long z;

            z = toUnsignedLong(srcm[m + u]) * toUnsignedLong(x) + cc;
            srcm[m + u] = (int)z & 0x7FFFFFFF;
            cc = (int)(z >> 31);
        }
        return cc;
    }

    /*
     * Reduce a big integer d modulo a small integer p.
     * Rules:
     *  d is unsigned
     *  p is prime
     *  2^30 < p < 2^31
     *  p0i = -(1/p) mod 2^31
     *  R2 = 2^62 mod p
     */
    int zint_mod_small_unsigned(int[] srcd, int d, int dlen,
                                int p, int p0i, int R2)
    {
        int x;
        int u;

        /*
         * Algorithm: we inject words one by one, starting with the high
         * word. Each step is:
         *  - multiply x by 2^31
         *  - add new word
         */
        x = 0;
        u = dlen;
        while (u-- > 0)
        {
            int w;

            x = modp_montymul(x, R2, p, p0i);
            w = srcd[d + u] - p;
            w += p & -(w >>> 31);
            x = modp_add(x, w, p);
        }
        return x;
    }

    /*
     * Similar to zint_mod_small_unsigned(), except that d may be signed.
     * Extra parameter is Rx = 2^(31*dlen) mod p.
     */
    int zint_mod_small_signed(int[] srcd, int d, int dlen,
                              int p, int p0i, int R2, int Rx)
    {
        int z;

        if (dlen == 0)
        {
            return 0;
        }
        z = zint_mod_small_unsigned(srcd, d, dlen, p, p0i, R2);
        z = modp_sub(z, Rx & -(srcd[d + dlen - 1] >>> 30), p);
        return z;
    }

    /*
     * Add y*s to x. x and y initially have length 'len' words; the new x
     * has length 'len+1' words. 's' must fit on 31 bits. x[] and y[] must
     * not overlap.
     */
    void zint_add_mul_small(int[] srcx, int x,
                            int[] srcy, int y, int len, int s)
    {
        int u;
        int cc;

        cc = 0;
        for (u = 0; u < len; u++)
        {
            int xw, yw;
            long z;

            xw = srcx[x + u];
            yw = srcy[y + u];
            z = toUnsignedLong(yw) * toUnsignedLong(s) + toUnsignedLong(xw) + toUnsignedLong(cc);
            srcx[x + u] = (int)z & 0x7FFFFFFF;
            cc = (int)(z >>> 31);
        }
        srcx[x + len] = cc;
    }

    /*
     * Normalize a modular integer around 0: if x > p/2, then x is replaced
     * with x - p (signed encoding with two's complement); otherwise, x is
     * untouched. The two integers x and p are encoded over the same length.
     */
    void zint_norm_zero(int[] srcx, int x, int[] srcp, int p, int len)
    {
        int u;
        int r, bb;

        /*
         * Compare x with p/2. We use the shifted version of p, and p
         * is odd, so we really compare with (p-1)/2; we want to perform
         * the subtraction if and only if x > (p-1)/2.
         */
        r = 0;
        bb = 0;
        u = len;
        while (u-- > 0)
        {
            int wx, wp, cc;

            /*
             * Get the two words to compare in wx and wp (both over
             * 31 bits exactly).
             */
            wx = srcx[x + u];
            wp = (srcp[p + u] >>> 1) | (bb << 30);
            bb = srcp[p + u] & 1;

            /*
             * We set cc to -1, 0 or 1, depending on whether wp is
             * lower than, equal to, or greater than wx.
             */
            cc = wp - wx;
            cc = ((-cc) >>> 31) | -(cc >>> 31);

            /*
             * If r != 0 then it is either 1 or -1, and we keep its
             * value. Otherwise, if r = 0, then we replace it with cc.
             */
            r |= cc & ((r & 1) - 1);
        }

        /*
         * At this point, r = -1, 0 or 1, depending on whether (p-1)/2
         * is lower than, equal to, or greater than x. We thus want to
         * do the subtraction only if r = -1.
         */
        zint_sub(srcx, x, srcp, p, len, r >>> 31);
    }

    /*
     * Rebuild integers from their RNS representation. There are 'num'
     * integers, and each consists in 'xlen' words. 'xx' points at that
     * first word of the first integer; subsequent integers are accessed
     * by adding 'xstride' repeatedly.
     *
     * The words of an integer are the RNS representation of that integer,
     * using the provided 'primes' are moduli. This function replaces
     * each integer with its multi-word value (little-endian order).
     *
     * If "normalize_signed" is non-zero, then the returned value is
     * normalized to the -m/2..m/2 interval (where m is the product of all
     * small prime moduli); two's complement is used for negative values.
     */
    void zint_rebuild_CRT(int[] srcxx, int xx, int xlen, int xstride,
                          int num, FalconSmallPrime[] primes, int normalize_signed,
                          int[] srctmp, int tmp)
    {
        int u;
        int x;

        srctmp[tmp + 0] = primes[0].p;
        for (u = 1; u < xlen; u++)
        {
            /*
             * At the entry of each loop iteration:
             *  - the first u words of each array have been
             *    reassembled;
             *  - the first u words of tmp[] contains the
             * product of the prime moduli processed so far.
             *
             * We call 'q' the product of all previous primes.
             */
            int p, p0i, s, R2;
            int v;

            p = primes[u].p;
            s = primes[u].s;
            p0i = modp_ninv31(p);
            R2 = modp_R2(p, p0i);

            for (v = 0, x = xx; v < num; v++, x += xstride)
            {
                int xp, xq, xr;
                /*
                 * xp = the integer x modulo the prime p for this
                 *      iteration
                 * xq = (x mod q) mod p
                 */
                xp = srcxx[x + u];
                xq = zint_mod_small_unsigned(srcxx, x, u, p, p0i, R2);

                /*
                 * New value is (x mod q) + q * (s * (xp - xq) mod p)
                 */
                xr = modp_montymul(s, modp_sub(xp, xq, p), p, p0i);
                zint_add_mul_small(srcxx, x, srctmp, tmp, u, xr);
            }

            /*
             * Update product of primes in tmp[].
             */
            srctmp[tmp + u] = zint_mul_small(srctmp, tmp, u, p);
        }

        /*
         * Normalize the reconstructed values around 0.
         */
        if (normalize_signed != 0)
        {
            for (u = 0, x = xx; u < num; u++, x += xstride)
            {
                zint_norm_zero(srcxx, x, srctmp, tmp, xlen);
            }
        }
    }

    /*
     * Negate a big integer conditionally: value a is replaced with -a if
     * and only if ctl = 1. Control value ctl must be 0 or 1.
     */
    void zint_negate(int[] srca, int a, int len, int ctl)
    {
        int u;
        int cc, m;

        /*
         * If ctl = 1 then we flip the bits of a by XORing with
         * 0x7FFFFFFF, and we add 1 to the value. If ctl = 0 then we XOR
         * with 0 and add 0, which leaves the value unchanged.
         */
        cc = ctl;
        m = -ctl >>> 1;
        for (u = 0; u < len; u++)
        {
            int aw;

            aw = srca[a + u];
            aw = (aw ^ m) + cc;
            srca[a + u] = aw & 0x7FFFFFFF;
            cc = aw >>> 31;
        }
    }

    /*
     * Replace a with (a*xa+b*xb)/(2^31) and b with (a*ya+b*yb)/(2^31).
     * The low bits are dropped (the caller should compute the coefficients
     * such that these dropped bits are all zeros). If either or both
     * yields a negative value, then the value is negated.
     *
     * Returned value is:
     *  0  both values were positive
     *  1  new a had to be negated
     *  2  new b had to be negated
     *  3  both new a and new b had to be negated
     *
     * Coefficients xa, xb, ya and yb may use the full signed 32-bit range.
     */
    int zint_co_reduce(int[] srca, int a, int[] srcb, int b, int len,
                       long xa, long xb, long ya, long yb)
    {
        int u;
        long cca, ccb;
        int nega, negb;

        cca = 0;
        ccb = 0;
        for (u = 0; u < len; u++)
        {
            int wa, wb;
            long za, zb;

            wa = srca[a + u];
            wb = srcb[b + u];
            za = wa * xa + wb * xb + cca;
            zb = wa * ya + wb * yb + ccb;
            if (u > 0)
            {
                srca[a + u - 1] = (int)za & 0x7FFFFFFF;
                srcb[b + u - 1] = (int)zb & 0x7FFFFFFF;
            }
//            cca = *(int64_t *)&za >> 31;
            cca = za >> 31;
//            ccb = *(int64_t *)&zb >> 31;
            ccb = zb >> 31;
        }
        srca[a + len - 1] = (int)cca;
        srcb[b + len - 1] = (int)ccb;

        nega = (int)(cca >>> 63);
        negb = (int)(ccb >>> 63);
        zint_negate(srca, a, len, nega);
        zint_negate(srcb, b, len, negb);
        return nega | (negb << 1);
    }

    /*
     * Finish modular reduction. Rules on input parameters:
     *
     *   if neg = 1, then -m <= a < 0
     *   if neg = 0, then 0 <= a < 2*m
     *
     * If neg = 0, then the top word of a[] is allowed to use 32 bits.
     *
     * Modulus m must be odd.
     */
    void zint_finish_mod(int[] srca, int a, int len, int[] srcm, int m, int neg)
    {
        int u;
        int cc, xm, ym;

        /*
         * First pass: compare a (assumed nonnegative) with m. Note that
         * if the top word uses 32 bits, subtracting m must yield a
         * value less than 2^31 since a < 2*m.
         */
        cc = 0;
        for (u = 0; u < len; u++)
        {
            cc = (srca[a + u] - srcm[m + u] - cc) >>> 31;
        }

        /*
         * If neg = 1 then we must add m (regardless of cc)
         * If neg = 0 and cc = 0 then we must subtract m
         * If neg = 0 and cc = 1 then we must do nothing
         *
         * In the loop below, we conditionally subtract either m or -m
         * from a. Word xm is a word of m (if neg = 0) or -m (if neg = 1);
         * but if neg = 0 and cc = 1, then ym = 0 and it forces mw to 0.
         */
        xm = -neg >>> 1;
        ym = -(neg | (1 - cc));
        cc = neg;
        for (u = 0; u < len; u++)
        {
            int aw, mw;

            aw = srca[a + u];
            mw = (srcm[m + u] ^ xm) & ym;
            aw = aw - mw - cc;
            srca[a + u] = aw & 0x7FFFFFFF;
            cc = aw >>> 31;
        }
    }

    /*
     * Replace a with (a*xa+b*xb)/(2^31) mod m, and b with
     * (a*ya+b*yb)/(2^31) mod m. Modulus m must be odd; m0i = -1/m[0] mod 2^31.
     */
    void zint_co_reduce_mod(int[] srca, int a, int[] srcb, int b, int[] srcm, int m, int len,
                            int m0i, long xa, long xb, long ya, long yb)
    {
        int u;
        long cca, ccb;
        int fa, fb;

        /*
         * These are actually four combined Montgomery multiplications.
         */
        cca = 0;
        ccb = 0;
        fa = ((srca[a + 0] * (int)xa + srcb[b + 0] * (int)xb) * m0i) & 0x7FFFFFFF;
        fb = ((srca[a + 0] * (int)ya + srcb[b + 0] * (int)yb) * m0i) & 0x7FFFFFFF;
        for (u = 0; u < len; u++)
        {
            int wa, wb;
            long za, zb;

            wa = srca[a + u];
            wb = srcb[b + u];
            za = wa * xa + wb * xb
                + srcm[m + u] * toUnsignedLong(fa) + cca;
            zb = wa * ya + wb * yb
                + srcm[m + u] * toUnsignedLong(fb) + ccb;
            if (u > 0)
            {
                srca[a + u - 1] = (int)za & 0x7FFFFFFF;
                srcb[b + u - 1] = (int)zb & 0x7FFFFFFF;
            }
            cca = za >> 31;
            ccb = zb >> 31;
        }
        srca[a + len - 1] = (int)cca;
        srcb[b + len - 1] = (int)ccb;

        /*
         * At this point:
         *   -m <= a < 2*m
         *   -m <= b < 2*m
         * (this is a case of Montgomery reduction)
         * The top words of 'a' and 'b' may have a 32-th bit set.
         * We want to add or subtract the modulus, as required.
         */
        zint_finish_mod(srca, a, len, srcm, m, (int)(cca >>> 63));
        zint_finish_mod(srcb, b, len, srcm, m, (int)(ccb >>> 63));
    }

    /*
     * Compute a GCD between two positive big integers x and y. The two
     * integers must be odd. Returned value is 1 if the GCD is 1, 0
     * otherwise. When 1 is returned, arrays u and v are filled with values
     * such that:
     *   0 <= u <= y
     *   0 <= v <= x
     *   x*u - y*v = 1
     * x[] and y[] are unmodified. Both input values must have the same
     * encoded length. Temporary array must be large enough to accommodate 4
     * extra values of that length. Arrays u, v and tmp may not overlap with
     * each other, or with either x or y.
     */
    int zint_bezout(int[] srcu, int u, int[] srcv, int v,
                    int[] srcx, int x, int[] srcy, int y,
                    int len, int[] srctmp, int tmp)
    {
        /*
         * Algorithm is an extended binary GCD. We maintain 6 values
         * a, b, u0, u1, v0 and v1 with the following invariants:
         *
         *  a = x*u0 - y*v0
         *  b = x*u1 - y*v1
         *  0 <= a <= x
         *  0 <= b <= y
         *  0 <= u0 < y
         *  0 <= v0 < x
         *  0 <= u1 <= y
         *  0 <= v1 < x
         *
         * Initial values are:
         *
         *  a = x   u0 = 1   v0 = 0
         *  b = y   u1 = y   v1 = x-1
         *
         * Each iteration reduces either a or b, and maintains the
         * invariants. Algorithm stops when a = b, at which point their
         * common value is GCD(a,b) and (u0,v0) (or (u1,v1)) contains
         * the values (u,v) we want to return.
         *
         * The formal definition of the algorithm is a sequence of steps:
         *
         *  - If a is even, then:
         *        a <- a/2
         *        u0 <- u0/2 mod y
         *        v0 <- v0/2 mod x
         *
         *  - Otherwise, if b is even, then:
         *        b <- b/2
         *        u1 <- u1/2 mod y
         *        v1 <- v1/2 mod x
         *
         *  - Otherwise, if a > b, then:
         *        a <- (a-b)/2
         *        u0 <- (u0-u1)/2 mod y
         *        v0 <- (v0-v1)/2 mod x
         *
         *  - Otherwise:
         *        b <- (b-a)/2
         *        u1 <- (u1-u0)/2 mod y
         *        v1 <- (v1-v0)/2 mod y
         *
         * We can show that the operations above preserve the invariants:
         *
         *  - If a is even, then u0 and v0 are either both even or both
         *    odd (since a = x*u0 - y*v0, and x and y are both odd).
         *    If u0 and v0 are both even, then (u0,v0) <- (u0/2,v0/2).
         *    Otherwise, (u0,v0) <- ((u0+y)/2,(v0+x)/2). Either way,
         *    the a = x*u0 - y*v0 invariant is preserved.
         *
         *  - The same holds for the case where b is even.
         *
         *  - If a and b are odd, and a > b, then:
         *
         *      a-b = x*(u0-u1) - y*(v0-v1)
         *
         *    In that situation, if u0 < u1, then x*(u0-u1) < 0, but
         *    a-b > 0; therefore, it must be that v0 < v1, and the
         *    first part of the update is: (u0,v0) <- (u0-u1+y,v0-v1+x),
         *    which preserves the invariants. Otherwise, if u0 > u1,
         *    then u0-u1 >= 1, thus x*(u0-u1) >= x. But a <= x and
         *    b >= 0, hence a-b <= x. It follows that, in that case,
         *    v0-v1 >= 0. The first part of the update is then:
         *    (u0,v0) <- (u0-u1,v0-v1), which again preserves the
         *    invariants.
         *
         *    Either way, once the subtraction is done, the new value of
         *    a, which is the difference of two odd values, is even,
         *    and the remaining of this step is a subcase of the
         *    first algorithm case (i.e. when a is even).
         *
         *  - If a and b are odd, and b > a, then the a similar
         *    argument holds.
         *
         * The values a and b start at x and y, respectively. Since x
         * and y are odd, their GCD is odd, and it is easily seen that
         * all steps conserve the GCD (GCD(a-b,b) = GCD(a, b);
         * GCD(a/2,b) = GCD(a,b) if GCD(a,b) is odd). Moreover, either a
         * or b is reduced by at least one bit at each iteration, so
         * the algorithm necessarily converges on the case a = b, at
         * which point the common value is the GCD.
         *
         * In the algorithm expressed above, when a = b, the fourth case
         * applies, and sets b = 0. Since a contains the GCD of x and y,
         * which are both odd, a must be odd, and subsequent iterations
         * (if any) will simply divide b by 2 repeatedly, which has no
         * consequence. Thus, the algorithm can run for more iterations
         * than necessary; the final GCD will be in a, and the (u,v)
         * coefficients will be (u0,v0).
         *
         *
         * The presentation above is bit-by-bit. It can be sped up by
         * noticing that all decisions are taken based on the low bits
         * and high bits of a and b. We can extract the two top words
         * and low word of each of a and b, and compute reduction
         * parameters pa, pb, qa and qb such that the new values for
         * a and b are:
         *    a' = (a*pa + b*pb) / (2^31)
         *    b' = (a*qa + b*qb) / (2^31)
         * the two divisions being exact. The coefficients are obtained
         * just from the extracted words, and may be slightly off, requiring
         * an optional correction: if a' < 0, then we replace pa with -pa
         * and pb with -pb. Each such step will reduce the total length
         * (sum of lengths of a and b) by at least 30 bits at each
         * iteration.
         */
        int u0, u1, v0, v1, a, b;
        int x0i, y0i;
        int num, rc;
        int j;

        if (len == 0)
        {
            return 0;
        }

        /*
         * u0 and v0 are the u and v result buffers; the four other
         * values (u1, v1, a and b) are taken from tmp[].
         */
        u0 = u;
        v0 = v;
        u1 = tmp;
        v1 = u1 + len;
        a = v1 + len;
        b = a + len;

        /*
         * We'll need the Montgomery reduction coefficients.
         */
        x0i = modp_ninv31(srcx[x + 0]);
        y0i = modp_ninv31(srcy[y + 0]);

        /*
         * Initialize a, b, u0, u1, v0 and v1.
         *  a = x   u0 = 1   v0 = 0
         *  b = y   u1 = y   v1 = x-1
         * Note that x is odd, so computing x-1 is easy.
         */
        // memcpy(a, x, len * sizeof *x);
        System.arraycopy(srcx, x, srctmp, a, len);
        // memcpy(b, y, len * sizeof *y);
        System.arraycopy(srcy, y, srctmp, b, len);
        // u0[0] = 1;
        srcu[u0 + 0] = 1;
        // memset(u0 + 1, 0, (len - 1) * sizeof *u0);
        // memset(v0, 0, len * sizeof *v0);
        srcv[v0 + 0] = 0;
        for (int i = 1; i < len; i++)
        {
            srcu[u0 + i] = 0;
            srcv[v0 + i] = 0;
        }
        // memcpy(u1, y, len * sizeof *u1);
        System.arraycopy(srcy, y, srctmp, u1, len);
        // memcpy(v1, x, len * sizeof *v1);
        System.arraycopy(srcx, x, srctmp, v1, len);
        // v1[0] --;
        srctmp[v1 + 0]--;
        /*
         * Each input operand may be as large as 31*len bits, and we
         * reduce the total length by at least 30 bits at each iteration.
         */
        for (num = 62 * len + 30; num >= 30; num -= 30)
        {
            int c0, c1;
            int a0, a1, b0, b1;
            long a_hi, b_hi;
            int a_lo, b_lo;
            long pa, pb, qa, qb;
            int i;
            int r;

            /*
             * Extract the top words of a and b. If j is the highest
             * index >= 1 such that a[j] != 0 or b[j] != 0, then we
             * want (a[j] << 31) + a[j-1] and (b[j] << 31) + b[j-1].
             * If a and b are down to one word each, then we use
             * a[0] and b[0].
             */
            c0 = -1;
            c1 = -1;
            a0 = 0;
            a1 = 0;
            b0 = 0;
            b1 = 0;
            j = len;
            while (j-- > 0)
            {
                int aw, bw;

                aw = srctmp[a + j];
                bw = srctmp[b + j];
                a0 ^= (a0 ^ aw) & c0;
                a1 ^= (a1 ^ aw) & c1;
                b0 ^= (b0 ^ bw) & c0;
                b1 ^= (b1 ^ bw) & c1;
                c1 = c0;
                c0 &= (((aw | bw) + 0x7FFFFFFF) >>> 31) - 1;
            }

            /*
             * If c1 = 0, then we grabbed two words for a and b.
             * If c1 != 0 but c0 = 0, then we grabbed one word. It
             * is not possible that c1 != 0 and c0 != 0, because that
             * would mean that both integers are zero.
             */
            a1 |= a0 & c1;
            a0 &= ~c1;
            b1 |= b0 & c1;
            b0 &= ~c1;
            a_hi = (toUnsignedLong(a0) << 31) + toUnsignedLong(a1);
            b_hi = (toUnsignedLong(b0) << 31) + toUnsignedLong(b1);
            a_lo = srctmp[a + 0];
            b_lo = srctmp[b + 0];

            /*
             * Compute reduction factors:
             *
             *   a' = a*pa + b*pb
             *   b' = a*qa + b*qb
             *
             * such that a' and b' are both multiple of 2^31, but are
             * only marginally larger than a and b.
             */
            pa = 1;
            pb = 0;
            qa = 0;
            qb = 1;
            for (i = 0; i < 31; i++)
            {
                /*
                 * At each iteration:
                 *
                 *   a <- (a-b)/2 if: a is odd, b is odd, a_hi > b_hi
                 *   b <- (b-a)/2 if: a is odd, b is odd, a_hi <= b_hi
                 *   a <- a/2 if: a is even
                 *   b <- b/2 if: a is odd, b is even
                 *
                 * We multiply a_lo and b_lo by 2 at each
                 * iteration, thus a division by 2 really is a
                 * non-multiplication by 2.
                 */
                int rt, oa, ob, cAB, cBA, cA;
                long rz;

                /*
                 * rt = 1 if a_hi > b_hi, 0 otherwise.
                 */
                rz = b_hi - a_hi;
                rt = (int)((rz ^ ((a_hi ^ b_hi)
                    & (a_hi ^ rz))) >>> 63);

                /*
                 * cAB = 1 if b must be subtracted from a
                 * cBA = 1 if a must be subtracted from b
                 * cA = 1 if a must be divided by 2
                 *
                 * Rules:
                 *
                 *   cAB and cBA cannot both be 1.
                 *   If a is not divided by 2, b is.
                 */
                oa = (a_lo >> i) & 1;
                ob = (b_lo >> i) & 1;
                cAB = oa & ob & rt;
                cBA = oa & ob & ~rt;
                cA = cAB | (oa ^ 1);

                /*
                 * Conditional subtractions.
                 */
                a_lo -= b_lo & -cAB;
                a_hi -= b_hi & -toUnsignedLong(cAB);
                pa -= qa & -(long)cAB;
                pb -= qb & -(long)cAB;
                b_lo -= a_lo & -cBA;
                b_hi -= a_hi & -toUnsignedLong(cBA);
                qa -= pa & -(long)cBA;
                qb -= pb & -(long)cBA;

                /*
                 * Shifting.
                 */
                a_lo += a_lo & (cA - 1);
                pa += pa & ((long)cA - 1);
                pb += pb & ((long)cA - 1);
                a_hi ^= (a_hi ^ (a_hi >> 1)) & -toUnsignedLong(cA);
                b_lo += b_lo & -cA;
                qa += qa & -(long)cA;
                qb += qb & -(long)cA;
                b_hi ^= (b_hi ^ (b_hi >> 1)) & (toUnsignedLong(cA) - 1);
            }

            /*
             * Apply the computed parameters to our values. We
             * may have to correct pa and pb depending on the
             * returned value of zint_co_reduce() (when a and/or b
             * had to be negated).
             */
            r = zint_co_reduce(srctmp, a, srctmp, b, len, pa, pb, qa, qb);
            pa -= (pa + pa) & -(long)(r & 1);
            pb -= (pb + pb) & -(long)(r & 1);
            qa -= (qa + qa) & -(long)(r >>> 1);
            qb -= (qb + qb) & -(long)(r >>> 1);
            zint_co_reduce_mod(srcu, u0, srctmp, u1, srcy, y, len, y0i, pa, pb, qa, qb);
            zint_co_reduce_mod(srcv, v0, srctmp, v1, srcx, x, len, x0i, pa, pb, qa, qb);
        }

        /*
         * At that point, array a[] should contain the GCD, and the
         * results (u,v) should already be set. We check that the GCD
         * is indeed 1. We also check that the two operands x and y
         * are odd.
         */
        rc = srctmp[a + 0] ^ 1;
        for (j = 1; j < len; j++)
        {
            rc |= srctmp[a + j];
        }
        return ((1 - ((rc | -rc) >>> 31)) & srcx[x + 0] & srcy[y + 0]);
    }

    /*
     * Add k*y*2^sc to x. The result is assumed to fit in the array of
     * size xlen (truncation is applied if necessary).
     * Scale factor 'sc' is provided as sch and scl, such that:
     *   sch = sc / 31
     *   scl = sc % 31
     * xlen MUST NOT be lower than ylen.
     *
     * x[] and y[] are both signed integers, using two's complement for
     * negative values.
     */
    void zint_add_scaled_mul_small(int[] srcx, int x, int xlen,
                                   int[] srcy, int y, int ylen, int k,
                                   int sch, int scl)
    {
        int u;
        int ysign, tw;
        int cc;

        if (ylen == 0)
        {
            return;
        }

        ysign = -(srcy[y + ylen - 1] >>> 30) >>> 1;
        tw = 0;
        cc = 0;
        for (u = sch; u < xlen; u++)
        {
            int v;
            int wy, wys, ccu;
            long z;

            /*
             * Get the next word of y (scaled).
             */
            v = u - sch;
            wy = v < ylen ? srcy[y + v] : ysign;
            wys = ((wy << scl) & 0x7FFFFFFF) | tw;
            tw = wy >>> (31 - scl);

            /*
             * The expression below does not overflow.
             */
            z = (toUnsignedLong(wys) * (long)k + toUnsignedLong(srcx[x + u]) + cc);
            srcx[x + u] = (int)z & 0x7FFFFFFF;

            /*
             * Right-shifting the signed value z would yield
             * implementation-defined results (arithmetic shift is
             * not guaranteed). However, we can cast to unsigned,
             * and get the next carry as an unsigned word. We can
             * then convert it back to signed by using the guaranteed
             * fact that 'int32_t' uses two's complement with no
             * trap representation or padding bit, and with a layout
             * compatible with that of 'uint32_t'.
             */
            ccu = (int)(z >>> 31);
            cc = ccu;
        }
    }

    /*
     * Subtract y*2^sc from x. The result is assumed to fit in the array of
     * size xlen (truncation is applied if necessary).
     * Scale factor 'sc' is provided as sch and scl, such that:
     *   sch = sc / 31
     *   scl = sc % 31
     * xlen MUST NOT be lower than ylen.
     *
     * x[] and y[] are both signed integers, using two's complement for
     * negative values.
     */
    void zint_sub_scaled(int[] srcx, int x, int xlen,
                         int[] srcy, int y, int ylen, int sch, int scl)
    {
        int u;
        int ysign, tw;
        int cc;

        if (ylen == 0)
        {
            return;
        }

        ysign = -(srcy[y + ylen - 1] >>> 30) >>> 1;
        tw = 0;
        cc = 0;
        for (u = sch; u < xlen; u++)
        {
            int v;
            int w, wy, wys;

            /*
             * Get the next word of y (scaled).
             */
            v = u - sch;
            wy = v < ylen ? srcy[y + v] : ysign;
            wys = ((wy << scl) & 0x7FFFFFFF) | tw;
            tw = wy >>> (31 - scl);

            w = srcx[x + u] - wys - cc;
            srcx[x + u] = w & 0x7FFFFFFF;
            cc = w >>> 31;
        }
    }

    /*
     * Convert a one-word signed big integer into a signed value.
     */
    int zint_one_to_plain(int[] srcx, int x)
    {
        int w;

        w = srcx[x + 0];
        w |= (w & 0x40000000) << 1;
        return w;
    }

    /* ==================================================================== */

    /*
     * Convert a polynomial to floating-point values.
     *
     * Each coefficient has length flen words, and starts fstride words after
     * the previous.
     *
     * IEEE-754 binary64 values can represent values in a finite range,
     * roughly 2^(-1023) to 2^(+1023); thus, if coefficients are too large,
     * they should be "trimmed" by pointing not to the lowest word of each,
     * but upper.
     */
    void poly_big_to_fp(FalconFPR[] srcd, int d, int[] srcf, int f, int flen, int fstride,
                        int logn)
    {
        int n, u;

        n = mkn(logn);
        if (flen == 0)
        {
            for (u = 0; u < n; u++)
            {
                srcd[d + u] = fpr.fpr_zero;
            }
            return;
        }
        for (u = 0; u < n; u++, f += fstride)
        {
            int v;
            int neg, cc, xm;
            FalconFPR x, fsc;

            /*
             * Get sign of the integer; if it is negative, then we
             * will load its absolute value instead, and negate the
             * result.
             */
            neg = -(srcf[f + flen - 1] >>> 30);
            xm = neg >>> 1;
            cc = neg & 1;
            x = fpr.fpr_zero;
            fsc = fpr.fpr_one;
            for (v = 0; v < flen; v++, fsc = fpr.fpr_mul(fsc, fpr.fpr_ptwo31))
            {
                int w;

                w = (srcf[f + v] ^ xm) + cc;
                cc = w >>> 31;
                w &= 0x7FFFFFFF;
                w -= (w << 1) & neg;
                x = fpr.fpr_add(x, fpr.fpr_mul(fpr.fpr_of(w), fsc));
            }
            srcd[d + u] = x;
        }
    }

    /*
     * Convert a polynomial to small integers. Source values are supposed
     * to be one-word integers, signed over 31 bits. Returned value is 0
     * if any of the coefficients exceeds the provided limit (in absolute
     * value), or 1 on success.
     *
     * This is not constant-time; this is not a problem here, because on
     * any failure, the NTRU-solving process will be deemed to have failed
     * and the (f,g) polynomials will be discarded.
     */
    int poly_big_to_small(byte[] srcd, int d, int[] srcs, int s, int lim, int logn)
    {
        int n, u;

        n = mkn(logn);
        for (u = 0; u < n; u++)
        {
            int z;

            z = zint_one_to_plain(srcs, s + u);
            if (z < -lim || z > lim)
            {
                return 0;
            }
            srcd[d + u] = (byte)z;
        }
        return 1;
    }

    /*
     * Subtract k*f from F, where F, f and k are polynomials modulo X^N+1.
     * Coefficients of polynomial k are small integers (signed values in the
     * -2^31..2^31 range) scaled by 2^sc. Value sc is provided as sch = sc / 31
     * and scl = sc % 31.
     *
     * This function implements the basic quadratic multiplication algorithm,
     * which is efficient in space (no extra buffer needed) but slow at
     * high degree.
     */
    void poly_sub_scaled(int[] srcF, int F, int Flen, int Fstride,
                         int[] srcf, int f, int flen, int fstride,
                         int[] srck, int k, int sch, int scl, int logn)
    {
        int n, u;

        n = mkn(logn);
        for (u = 0; u < n; u++)
        {
            int kf;
            int v;
            int x;
            int y;

            kf = -srck[k + u];
            x = F + u * Fstride;
            y = f;
            for (v = 0; v < n; v++)
            {
                zint_add_scaled_mul_small(srcF,
                    x, Flen, srcf, y, flen, kf, sch, scl);
                if (u + v == n - 1)
                {
                    x = F;
                    kf = -kf;
                }
                else
                {
                    x += Fstride;
                }
                y += fstride;
            }
        }
    }

    /*
     * Subtract k*f from F. Coefficients of polynomial k are small integers
     * (signed values in the -2^31..2^31 range) scaled by 2^sc. This function
     * assumes that the degree is large, and integers relatively small.
     * The value sc is provided as sch = sc / 31 and scl = sc % 31.
     */
    void poly_sub_scaled_ntt(int[] srcF, int F, int Flen, int Fstride,
                             int[] srcf, int f, int flen, int fstride,
                             int[] srck, int k, int sch, int scl, int logn,
                             int[] srctmp, int tmp)
    {
        int gm, igm, fk, t1, x;
        int y;
        int n, u, tlen;
        FalconSmallPrime[] primes;

        n = mkn(logn);
        tlen = flen + 1;
        gm = tmp;
        igm = gm + mkn(logn);
        fk = igm + mkn(logn);
        t1 = fk + n * tlen;

        primes = this.primes.PRIMES;

        /*
         * Compute k*f in fk[], in RNS notation.
         */
        for (u = 0; u < tlen; u++)
        {
            int p, p0i, R2, Rx;
            int v;

            p = primes[u].p;
            p0i = modp_ninv31(p);
            R2 = modp_R2(p, p0i);
            Rx = modp_Rx(flen, p, p0i, R2);
            modp_mkgm2(srctmp, gm, srctmp, igm, logn, primes[u].g, p, p0i);

            for (v = 0; v < n; v++)
            {
                srctmp[t1 + v] = modp_set(srck[k + v], p);
            }
            modp_NTT2(srctmp, t1, srctmp, gm, logn, p, p0i);
            for (v = 0, y = f, x = fk + u;
                 v < n; v++, y += fstride, x += tlen)
            {
                srctmp[x] = zint_mod_small_signed(srcf, y, flen, p, p0i, R2, Rx);
            }
            modp_NTT2_ext(srctmp, fk + u, tlen, srctmp, gm, logn, p, p0i);
            for (v = 0, x = fk + u; v < n; v++, x += tlen)
            {
                srctmp[x] = modp_montymul(
                    modp_montymul(srctmp[t1 + v], srctmp[x], p, p0i), R2, p, p0i);
            }
            modp_iNTT2_ext(srctmp, fk + u, tlen, srctmp, igm, logn, p, p0i);
        }

        /*
         * Rebuild k*f.
         */
        zint_rebuild_CRT(srctmp, fk, tlen, tlen, n, primes, 1, srctmp, t1);

        /*
         * Subtract k*f, scaled, from F.
         */
        for (u = 0, x = F, y = fk; u < n; u++, x += Fstride, y += tlen)
        {
            zint_sub_scaled(srcF, x, Flen, srctmp, y, tlen, sch, scl);
        }
    }

    /* ==================================================================== */

    /*
     * Get a random 8-byte integer from a SHAKE-based RNG. This function
     * ensures consistent interpretation of the SHAKE output so that
     * the same values will be obtained over different platforms, in case
     * a known seed is used.
     */
    long get_rng_u64(SHAKE256 rng)
    {
        /*
         * We enforce little-endian representation.
         */

        byte[] tmp = new byte[8];

        rng.inner_shake256_extract(tmp, 0, tmp.length);
        return (tmp[0] & 0xffL)
            | ((tmp[1] & 0xffL) << 8)
            | ((tmp[2] & 0xffL) << 16)
            | ((tmp[3] & 0xffL) << 24)
            | ((tmp[4] & 0xffL) << 32)
            | ((tmp[5] & 0xffL) << 40)
            | ((tmp[6] & 0xffL) << 48)
            | ((tmp[7] & 0xffL) << 56);
    }


    /*
     * Table below incarnates a discrete Gaussian distribution:
     *    D(x) = exp(-(x^2)/(2*sigma^2))
     * where sigma = 1.17*sqrt(q/(2*N)), q = 12289, and N = 1024.
     * Element 0 of the table is P(x = 0).
     * For k > 0, element k is P(x >= k+1 | x > 0).
     * Probabilities are scaled up by 2^63.
     */
    final long[] gauss_1024_12289 = {
        1283868770400643928l, 6416574995475331444l, 4078260278032692663l,
        2353523259288686585l, 1227179971273316331l, 575931623374121527l,
        242543240509105209l, 91437049221049666l, 30799446349977173l,
        9255276791179340l, 2478152334826140l, 590642893610164l,
        125206034929641l, 23590435911403l, 3948334035941l,
        586753615614l, 77391054539l, 9056793210l,
        940121950l, 86539696l, 7062824l,
        510971l, 32764l, 1862l,
        94l, 4l, 0l
    };

    /*
     * Generate a random value with a Gaussian distribution centered on 0.
     * The RNG must be ready for extraction (already flipped).
     *
     * Distribution has standard deviation 1.17*sqrt(q/(2*N)). The
     * precomputed table is for N = 1024. Since the sum of two independent
     * values of standard deviation sigma has standard deviation
     * sigma*sqrt(2), then we can just generate more values and add them
     * together for lower dimensions.
     */
    int mkgauss(SHAKE256 rng, int logn)
    {
        int u, g;
        int val;

        g = 1 << (10 - logn);
        val = 0;
        for (u = 0; u < g; u++)
        {
            /*
             * Each iteration generates one value with the
             * Gaussian distribution for N = 1024.
             *
             * We use two random 64-bit values. First value
             * decides on whether the generated value is 0, and,
             * if not, the sign of the value. Second random 64-bit
             * word is used to generate the non-zero value.
             *
             * For constant-time code we have to read the complete
             * table. This has negligible cost, compared with the
             * remainder of the keygen process (solving the NTRU
             * equation).
             */
            long r;
            int f, v, k, neg;

            /*
             * First value:
             *  - flag 'neg' is randomly selected to be 0 or 1.
             *  - flag 'f' is set to 1 if the generated value is zero,
             *    or set to 0 otherwise.
             */
            r = get_rng_u64(rng);
            neg = (int)(r >>> 63);
            r &= ~(1l << 63);
            f = (int)((r - gauss_1024_12289[0]) >>> 63);

            /*
             * We produce a new random 63-bit integer r, and go over
             * the array, starting at index 1. We store in v the
             * index of the first array element which is not greater
             * than r, unless the flag f was already 1.
             */
            v = 0;
            r = get_rng_u64(rng);
            r &= ~(1l << 63);
            for (k = 1; k < gauss_1024_12289.length; k++)
            {
                int t;

                t = (int)((r - gauss_1024_12289[k]) >>> 63) ^ 1;
                v |= k & -(t & (f ^ 1));
                f |= t;
            }

            /*
             * We apply the sign ('neg' flag). If the value is zero,
             * the sign has no effect.
             */
            v = (v ^ -neg) + neg;

            /*
             * Generated value is added to val.
             */
            val += v;
        }
        return val;
    }

    /*
     * The MAX_BL_SMALL[] and MAX_BL_LARGE[] contain the lengths, in 31-bit
     * words, of intermediate values in the computation:
     *
     *   MAX_BL_SMALL[depth]: length for the input f and g at that depth
     *   MAX_BL_LARGE[depth]: length for the unreduced F and G at that depth
     *
     * Rules:
     *
     *  - Within an array, values grow.
     *
     *  - The 'SMALL' array must have an entry for maximum depth, corresponding
     *    to the size of values used in the binary GCD. There is no such value
     *    for the 'LARGE' array (the binary GCD yields already reduced
     *    coefficients).
     *
     *  - MAX_BL_LARGE[depth] >= MAX_BL_SMALL[depth + 1].
     *
     *  - Values must be large enough to handle the common cases, with some
     *    margins.
     *
     *  - Values must not be "too large" either because we will convert some
     *    integers into floating-point values by considering the top 10 words,
     *    i.e. 310 bits; hence, for values of length more than 10 words, we
     *    should take care to have the length centered on the expected size.
     *
     * The following average lengths, in bits, have been measured on thousands
     * of random keys (fg = max length of the absolute value of coefficients
     * of f and g at that depth; FG = idem for the unreduced F and G; for the
     * maximum depth, F and G are the output of binary GCD, multiplied by q;
     * for each value, the average and standard deviation are provided).
     *
     * Binary case:
     *    depth: 10    fg: 6307.52 (24.48)    FG: 6319.66 (24.51)
     *    depth:  9    fg: 3138.35 (12.25)    FG: 9403.29 (27.55)
     *    depth:  8    fg: 1576.87 ( 7.49)    FG: 4703.30 (14.77)
     *    depth:  7    fg:  794.17 ( 4.98)    FG: 2361.84 ( 9.31)
     *    depth:  6    fg:  400.67 ( 3.10)    FG: 1188.68 ( 6.04)
     *    depth:  5    fg:  202.22 ( 1.87)    FG:  599.81 ( 3.87)
     *    depth:  4    fg:  101.62 ( 1.02)    FG:  303.49 ( 2.38)
     *    depth:  3    fg:   50.37 ( 0.53)    FG:  153.65 ( 1.39)
     *    depth:  2    fg:   24.07 ( 0.25)    FG:   78.20 ( 0.73)
     *    depth:  1    fg:   10.99 ( 0.08)    FG:   39.82 ( 0.41)
     *    depth:  0    fg:    4.00 ( 0.00)    FG:   19.61 ( 0.49)
     *
     * Integers are actually represented either in binary notation over
     * 31-bit words (signed, using two's complement), or in RNS, modulo
     * many small primes. These small primes are close to, but slightly
     * lower than, 2^31. Use of RNS loses less than two bits, even for
     * the largest values.
     *
     * IMPORTANT: if these values are modified, then the temporary buffer
     * sizes (FALCON_KEYGEN_TEMP_*, in inner.h) must be recomputed
     * accordingly.
     */

    final int[] MAX_BL_SMALL = {
        1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209
    };

    final int[] MAX_BL_LARGE = {
        2, 2, 5, 7, 12, 21, 40, 78, 157, 308
    };

    /*
     * Average and standard deviation for the maximum size (in bits) of
     * coefficients of (f,g), depending on depth. These values are used
     * to compute bounds for Babai's reduction.
     */
    final int[] bitlength_avg = {
        4,
        11,
        24,
        50,
        102,
        202,
        401,
        794,
        1577,
        3138,
        6308
    };
    final int[] bitlength_std = {
        0,
        1,
        1,
        1,
        1,
        2,
        4,
        5,
        8,
        13,
        25
    };

    /*
     * Minimal recursion depth at which we rebuild intermediate values
     * when reconstructing f and g.
     */
    final int DEPTH_INT_FG = 4;

    /*
     * Compute squared norm of a short vector. Returned value is saturated to
     * 2^32-1 if it is not lower than 2^31.
     */
    int poly_small_sqnorm(byte[] srcf, int f, int logn)
    {
        int n, u;
        int s, ng;

        n = mkn(logn);
        s = 0;
        ng = 0;
        for (u = 0; u < n; u++)
        {
            int z;

            z = srcf[f + u];
            s += (z * z);
            ng |= s;
        }
        return s | -(ng >>> 31);
    }

    /*
     * Convert a small vector to floating point.
     */
    void poly_small_to_fp(FalconFPR[] srcx, int x, byte[] srcf, int f, int logn)
    {
        int n, u;

        n = mkn(logn);
        for (u = 0; u < n; u++)
        {
            srcx[x + u] = fpr.fpr_of(srcf[f + u]);
        }
    }

    /*
     * Input: f,g of degree N = 2^logn; 'depth' is used only to get their
     * individual length.
     *
     * Output: f',g' of degree N/2, with the length for 'depth+1'.
     *
     * Values are in RNS; input and/or output may also be in NTT.
     */
    void make_fg_step(int[] srcdata, int data, int logn, int depth,
                      int in_ntt, int out_ntt)
    {
        int n, hn, u;
        int slen, tlen;
        int fd, gd, fs, gs, gm, igm, t1;
        FalconSmallPrime[] primes;

        n = 1 << logn;
        hn = n >> 1;
        slen = MAX_BL_SMALL[depth];
        tlen = MAX_BL_SMALL[depth + 1];
        primes = this.primes.PRIMES;

        /*
         * Prepare room for the result.
         */
        fd = data;
        gd = fd + hn * tlen;
        fs = gd + hn * tlen;
        gs = fs + n * slen;
        gm = gs + n * slen;
        igm = gm + n;
        t1 = igm + n;
//        memmove(fs, data, 2 * n * slen * sizeof *data);
        System.arraycopy(srcdata, data, srcdata, fs, 2 * n * slen);

        /*
         * First slen words: we use the input values directly, and apply
         * inverse NTT as we go.
         */
        for (u = 0; u < slen; u++)
        {
            int p, p0i, R2;
            int v;
            int x;

            p = primes[u].p;
            p0i = modp_ninv31(p);
            R2 = modp_R2(p, p0i);
            modp_mkgm2(srcdata, gm, srcdata, igm, logn, primes[u].g, p, p0i);

            for (v = 0, x = fs + u; v < n; v++, x += slen)
            {
                srcdata[t1 + v] = srcdata[x];
            }
            if (in_ntt == 0)
            {
                modp_NTT2(srcdata, t1, srcdata, gm, logn, p, p0i);
            }
            for (v = 0, x = fd + u; v < hn; v++, x += tlen)
            {
                int w0, w1;

                w0 = srcdata[t1 + (v << 1) + 0];
                w1 = srcdata[t1 + (v << 1) + 1];
                srcdata[x] = modp_montymul(
                    modp_montymul(w0, w1, p, p0i), R2, p, p0i);
            }
            if (in_ntt != 0)
            {
                modp_iNTT2_ext(srcdata, fs + u, slen, srcdata, igm, logn, p, p0i);
            }

            for (v = 0, x = gs + u; v < n; v++, x += slen)
            {
                srcdata[t1 + v] = srcdata[x];
            }
            if (in_ntt == 0)
            {
                modp_NTT2(srcdata, t1, srcdata, gm, logn, p, p0i);
            }
            for (v = 0, x = gd + u; v < hn; v++, x += tlen)
            {
                int w0, w1;

                w0 = srcdata[t1 + (v << 1) + 0];
                w1 = srcdata[t1 + (v << 1) + 1];
                srcdata[x] = modp_montymul(
                    modp_montymul(w0, w1, p, p0i), R2, p, p0i);
            }
            if (in_ntt != 0)
            {
                modp_iNTT2_ext(srcdata, gs + u, slen, srcdata, igm, logn, p, p0i);
            }

            if (out_ntt == 0)
            {
                modp_iNTT2_ext(srcdata, fd + u, tlen, srcdata, igm, logn - 1, p, p0i);
                modp_iNTT2_ext(srcdata, gd + u, tlen, srcdata, igm, logn - 1, p, p0i);
            }
        }

        /*
         * Since the fs and gs words have been de-NTTized, we can use the
         * CRT to rebuild the values.
         */
        zint_rebuild_CRT(srcdata, fs, slen, slen, n, primes, 1, srcdata, gm);
        zint_rebuild_CRT(srcdata, gs, slen, slen, n, primes, 1, srcdata, gm);

        /*
         * Remaining words: use modular reductions to extract the values.
         */
        for (u = slen; u < tlen; u++)
        {
            int p, p0i, R2, Rx;
            int v;
            int x;

            p = primes[u].p;
            p0i = modp_ninv31(p);
            R2 = modp_R2(p, p0i);
            Rx = modp_Rx(slen, p, p0i, R2);
            modp_mkgm2(srcdata, gm, srcdata, igm, logn, primes[u].g, p, p0i);
            for (v = 0, x = fs; v < n; v++, x += slen)
            {
                srcdata[t1 + v] = zint_mod_small_signed(srcdata, x, slen, p, p0i, R2, Rx);
            }
            modp_NTT2(srcdata, t1, srcdata, gm, logn, p, p0i);
            for (v = 0, x = fd + u; v < hn; v++, x += tlen)
            {
                int w0, w1;

                w0 = srcdata[t1 + (v << 1) + 0];
                w1 = srcdata[t1 + (v << 1) + 1];
                srcdata[x] = modp_montymul(
                    modp_montymul(w0, w1, p, p0i), R2, p, p0i);
            }
            for (v = 0, x = gs; v < n; v++, x += slen)
            {
                srcdata[t1 + v] = zint_mod_small_signed(srcdata, x, slen, p, p0i, R2, Rx);
            }
            modp_NTT2(srcdata, t1, srcdata, gm, logn, p, p0i);
            for (v = 0, x = gd + u; v < hn; v++, x += tlen)
            {
                int w0, w1;

                w0 = srcdata[t1 + (v << 1) + 0];
                w1 = srcdata[t1 + (v << 1) + 1];
                srcdata[x] = modp_montymul(
                    modp_montymul(w0, w1, p, p0i), R2, p, p0i);
            }

            if (out_ntt == 0)
            {
                modp_iNTT2_ext(srcdata, fd + u, tlen, srcdata, igm, logn - 1, p, p0i);
                modp_iNTT2_ext(srcdata, gd + u, tlen, srcdata, igm, logn - 1, p, p0i);
            }
        }
    }

    /* d values are stored in the data[] array, at slen words per integer.
     *
     * Conditions:
     *   0 <= depth <= logn
     *
     * Space use in data[]: enough room for any two successive values (f', g',
     * f and g).
     */
    void make_fg(int[] srcdata, int data, byte[] srcf, int f, byte[] srcg, int g,
                 int logn, int depth, int out_ntt)
    {
        int n, u;
        int ft, gt, p0;
        int d;
        FalconSmallPrime[] primes;

        n = mkn(logn);
        ft = data;
        gt = ft + n;
        primes = this.primes.PRIMES;
        p0 = primes[0].p;
        for (u = 0; u < n; u++)
        {
            srcdata[ft + u] = modp_set(srcf[f + u], p0);
            srcdata[gt + u] = modp_set(srcg[g + u], p0);
        }

        if (depth == 0 && out_ntt != 0)
        {
            int gm, igm;
            int p, p0i;

            p = primes[0].p;
            p0i = modp_ninv31(p);
            gm = gt + n;
            igm = gm + n;
            modp_mkgm2(srcdata, gm, srcdata, igm, logn, primes[0].g, p, p0i);
            modp_NTT2(srcdata, ft, srcdata, gm, logn, p, p0i);
            modp_NTT2(srcdata, gt, srcdata, gm, logn, p, p0i);
            return;
        }

        for (d = 0; d < depth; d++)
        {
            make_fg_step(srcdata, data, logn - d, d,
                d != 0 ? 1 : 0, ((d + 1) < depth || out_ntt != 0) ? 1 : 0);
        }
    }

    /*
     * Solving the NTRU equation, deepest level: compute the resultants of
     * f and g with X^N+1, and use binary GCD. The F and G values are
     * returned in tmp[].
     *
     * Returned value: 1 on success, 0 on error.
     */
    int solve_NTRU_deepest(int logn_top,
                           byte[] srcf, int f, byte[] srcg, int g, int[] srctmp, int tmp)
    {
        int len;
        int Fp, Gp, fp, gp, t1, q;
        FalconSmallPrime[] primes;

        len = MAX_BL_SMALL[logn_top];
        primes = this.primes.PRIMES;

        Fp = tmp;
        Gp = Fp + len;
        fp = Gp + len;
        gp = fp + len;
        t1 = gp + len;

        make_fg(srctmp, fp, srcf, f, srcg, g, logn_top, logn_top, 0);

        /*
         * We use the CRT to rebuild the resultants as big integers.
         * There are two such big integers. The resultants are always
         * nonnegative.
         */
        zint_rebuild_CRT(srctmp, fp, len, len, 2, primes, 0, srctmp, t1);

        /*
         * Apply the binary GCD. The zint_bezout() function works only
         * if both inputs are odd.
         *
         * We can test on the result and return 0 because that would
         * imply failure of the NTRU solving equation, and the (f,g)
         * values will be abandoned in that case.
         */
        if (zint_bezout(srctmp, Gp, srctmp, Fp, srctmp, fp, srctmp, gp, len, srctmp, t1) == 0)
        {
            return 0;
        }

        /*
         * Multiply the two values by the target value q. Values must
         * fit in the destination arrays.
         * We can again test on the returned words: a non-zero output
         * of zint_mul_small() means that we exceeded our array
         * capacity, and that implies failure and rejection of (f,g).
         */
        q = 12289;
        if (zint_mul_small(srctmp, Fp, len, q) != 0
            || zint_mul_small(srctmp, Gp, len, q) != 0)
        {
            return 0;
        }

        return 1;
    }

    /*
     * Solving the NTRU equation, intermediate level. Upon entry, the F and G
     * from the previous level should be in the tmp[] array.
     * This function MAY be invoked for the top-level (in which case depth = 0).
     *
     * Returned value: 1 on success, 0 on error.
     */
    int solve_NTRU_intermediate(int logn_top,
                                byte[] srcf, int f, byte[] srcg, int g, int depth, int[] srctmp, int tmp)
    {
        /*
         * In this function, 'logn' is the log2 of the degree for
         * this step. If N = 2^logn, then:
         *  - the F and G values already in fk->tmp (from the deeper
         *    levels) have degree N/2;
         *  - this function should return F and G of degree N.
         */
        int logn;
        int n, hn, slen, dlen, llen, rlen, FGlen, u;
        int Fd, Gd, Ft, Gt, ft, gt, t1;
        FalconFPR[] rt1, rt2, rt3, rt4, rt5;
        int scale_fg, minbl_fg, maxbl_fg, maxbl_FG, scale_k;
        int x, y;
        int[] k;
        FalconSmallPrime[] primes;

        logn = logn_top - depth;
        n = 1 << logn;
        hn = n >> 1;

        /*
         * slen = size for our input f and g; also size of the reduced
         *        F and G we return (degree N)
         *
         * dlen = size of the F and G obtained from the deeper level
         *        (degree N/2 or N/3)
         *
         * llen = size for intermediary F and G before reduction (degree N)
         *
         * We build our non-reduced F and G as two independent halves each,
         * of degree N/2 (F = F0 + X*F1, G = G0 + X*G1).
         */
        slen = MAX_BL_SMALL[depth];
        dlen = MAX_BL_SMALL[depth + 1];
        llen = MAX_BL_LARGE[depth];
        primes = this.primes.PRIMES;

        /*
         * Fd and Gd are the F and G from the deeper level.
         */
        Fd = tmp;
        Gd = Fd + dlen * hn;

        /*
         * Compute the input f and g for this level. Note that we get f
         * and g in RNS + NTT representation.
         */
        ft = Gd + dlen * hn;
        make_fg(srctmp, ft, srcf, f, srcg, g, logn_top, depth, 1);

        /*
         * Move the newly computed f and g to make room for our candidate
         * F and G (unreduced).
         */
        Ft = tmp;
        Gt = Ft + n * llen;
        t1 = Gt + n * llen;
//        memmove(t1, ft, 2 * n * slen * sizeof *ft);
        System.arraycopy(srctmp, ft, srctmp, t1, 2 * n * slen);
        ft = t1;
        gt = ft + slen * n;
        t1 = gt + slen * n;

        /*
         * Move Fd and Gd _after_ f and g.
         */
//        memmove(t1, Fd, 2 * hn * dlen * sizeof *Fd);
        System.arraycopy(srctmp, Fd, srctmp, t1, 2 * hn * dlen);
        Fd = t1;
        Gd = Fd + hn * dlen;

        /*
         * We reduce Fd and Gd modulo all the small primes we will need,
         * and store the values in Ft and Gt (only n/2 values in each).
         */
        for (u = 0; u < llen; u++)
        {
            int p, p0i, R2, Rx;
            int v;
            int xs, ys, xd, yd;

            p = primes[u].p;
            p0i = modp_ninv31(p);
            R2 = modp_R2(p, p0i);
            Rx = modp_Rx(dlen, p, p0i, R2);
            for (v = 0, xs = Fd, ys = Gd, xd = Ft + u, yd = Gt + u;
                 v < hn;
                 v++, xs += dlen, ys += dlen, xd += llen, yd += llen)
            {
                srctmp[xd] = zint_mod_small_signed(srctmp, xs, dlen, p, p0i, R2, Rx);
                srctmp[yd] = zint_mod_small_signed(srctmp, ys, dlen, p, p0i, R2, Rx);
            }
        }

        /*
         * We do not need Fd and Gd after that point.
         */

        /*
         * Compute our F and G modulo sufficiently many small primes.
         */
        for (u = 0; u < llen; u++)
        {
            int p, p0i, R2;
            int gm, igm, fx, gx, Fp, Gp;
            int v;

            /*
             * All computations are done modulo p.
             */
            p = primes[u].p;
            p0i = modp_ninv31(p);
            R2 = modp_R2(p, p0i);

            /*
             * If we processed slen words, then f and g have been
             * de-NTTized, and are in RNS; we can rebuild them.
             */
            if (u == slen)
            {
                zint_rebuild_CRT(srctmp, ft, slen, slen, n, primes, 1, srctmp, t1);
                zint_rebuild_CRT(srctmp, gt, slen, slen, n, primes, 1, srctmp, t1);
            }

            gm = t1;
            igm = gm + n;
            fx = igm + n;
            gx = fx + n;

            modp_mkgm2(srctmp, gm, srctmp, igm, logn, primes[u].g, p, p0i);

            if (u < slen)
            {
                for (v = 0, x = ft + u, y = gt + u;
                     v < n; v++, x += slen, y += slen)
                {
                    srctmp[fx + v] = srctmp[x];
                    srctmp[gx + v] = srctmp[y];
                }
                modp_iNTT2_ext(srctmp, ft + u, slen, srctmp, igm, logn, p, p0i);
                modp_iNTT2_ext(srctmp, gt + u, slen, srctmp, igm, logn, p, p0i);
            }
            else
            {
                int Rx;

                Rx = modp_Rx(slen, p, p0i, R2);
                for (v = 0, x = ft, y = gt;
                     v < n; v++, x += slen, y += slen)
                {
                    srctmp[fx + v] = zint_mod_small_signed(srctmp, x, slen,
                        p, p0i, R2, Rx);
                    srctmp[gx + v] = zint_mod_small_signed(srctmp, y, slen,
                        p, p0i, R2, Rx);
                }
                modp_NTT2(srctmp, fx, srctmp, gm, logn, p, p0i);
                modp_NTT2(srctmp, gx, srctmp, gm, logn, p, p0i);
            }

            /*
             * Get F' and G' modulo p and in NTT representation
             * (they have degree n/2). These values were computed in
             * a previous step, and stored in Ft and Gt.
             */
            Fp = gx + n;
            Gp = Fp + hn;
            for (v = 0, x = Ft + u, y = Gt + u;
                 v < hn; v++, x += llen, y += llen)
            {
                srctmp[Fp + v] = srctmp[x];
                srctmp[Gp + v] = srctmp[y];
            }
            modp_NTT2(srctmp, Fp, srctmp, gm, logn - 1, p, p0i);
            modp_NTT2(srctmp, Gp, srctmp, gm, logn - 1, p, p0i);

            /*
             * Compute our F and G modulo p.
             *
             * General case:
             *
             *   we divide degree by d = 2 or 3
             *   f'(x^d) = N(f)(x^d) = f * adj(f)
             *   g'(x^d) = N(g)(x^d) = g * adj(g)
             *   f'*G' - g'*F' = q
             *   F = F'(x^d) * adj(g)
             *   G = G'(x^d) * adj(f)
             *
             * We compute things in the NTT. We group roots of phi
             * such that all roots x in a group share the same x^d.
             * If the roots in a group are x_1, x_2... x_d, then:
             *
             *   N(f)(x_1^d) = f(x_1)*f(x_2)*...*f(x_d)
             *
             * Thus, we have:
             *
             *   G(x_1) = f(x_2)*f(x_3)*...*f(x_d)*G'(x_1^d)
             *   G(x_2) = f(x_1)*f(x_3)*...*f(x_d)*G'(x_1^d)
             *   ...
             *   G(x_d) = f(x_1)*f(x_2)*...*f(x_{d-1})*G'(x_1^d)
             *
             * In all cases, we can thus compute F and G in NTT
             * representation by a few simple multiplications.
             * Moreover, in our chosen NTT representation, roots
             * from the same group are consecutive in RAM.
             */
            for (v = 0, x = Ft + u, y = Gt + u; v < hn;
                 v++, x += (llen << 1), y += (llen << 1))
            {
                int ftA, ftB, gtA, gtB;
                int mFp, mGp;

                ftA = srctmp[fx + (v << 1) + 0];
                ftB = srctmp[fx + (v << 1) + 1];
                gtA = srctmp[gx + (v << 1) + 0];
                gtB = srctmp[gx + (v << 1) + 1];
                mFp = modp_montymul(srctmp[Fp + v], R2, p, p0i);
                mGp = modp_montymul(srctmp[Gp + v], R2, p, p0i);
                srctmp[x + 0] = modp_montymul(gtB, mFp, p, p0i);
                srctmp[x + llen] = modp_montymul(gtA, mFp, p, p0i);
                srctmp[y + 0] = modp_montymul(ftB, mGp, p, p0i);
                srctmp[y + llen] = modp_montymul(ftA, mGp, p, p0i);
            }
            modp_iNTT2_ext(srctmp, Ft + u, llen, srctmp, igm, logn, p, p0i);
            modp_iNTT2_ext(srctmp, Gt + u, llen, srctmp, igm, logn, p, p0i);
        }

        /*
         * Rebuild F and G with the CRT.
         */
        zint_rebuild_CRT(srctmp, Ft, llen, llen, n, primes, 1, srctmp, t1);
        zint_rebuild_CRT(srctmp, Gt, llen, llen, n, primes, 1, srctmp, t1);

        /*
         * At that point, Ft, Gt, ft and gt are consecutive in RAM (in that
         * order).
         */

        /*
         * Apply Babai reduction to bring back F and G to size slen.
         *
         * We use the FFT to compute successive approximations of the
         * reduction coefficient. We first isolate the top bits of
         * the coefficients of f and g, and convert them to floating
         * point; with the FFT, we compute adj(f), adj(g), and
         * 1/(f*adj(f)+g*adj(g)).
         *
         * Then, we repeatedly apply the following:
         *
         *   - Get the top bits of the coefficients of F and G into
         *     floating point, and use the FFT to compute:
         *        (F*adj(f)+G*adj(g))/(f*adj(f)+g*adj(g))
         *
         *   - Convert back that value into normal representation, and
         *     round it to the nearest integers, yielding a polynomial k.
         *     Proper scaling is applied to f, g, F and G so that the
         *     coefficients fit on 32 bits (signed).
         *
         *   - Subtract k*f from F and k*g from G.
         *
         * Under normal conditions, this process reduces the size of F
         * and G by some bits at each iteration. For constant-time
         * operation, we do not want to measure the actual length of
         * F and G; instead, we do the following:
         *
         *   - f and g are converted to floating-point, with some scaling
         *     if necessary to keep values in the representable range.
         *
         *   - For each iteration, we _assume_ a maximum size for F and G,
         *     and use the values at that size. If we overreach, then
         *     we get zeros, which is harmless: the resulting coefficients
         *     of k will be 0 and the value won't be reduced.
         *
         *   - We conservatively assume that F and G will be reduced by
         *     at least 25 bits at each iteration.
         *
         * Even when reaching the bottom of the reduction, reduction
         * coefficient will remain low. If it goes out-of-range, then
         * something wrong occurred and the whole NTRU solving fails.
         */

        /*
         * Memory layout:
         *  - We need to compute and keep adj(f), adj(g), and
         *    1/(f*adj(f)+g*adj(g)) (sizes N, N and N/2 fp numbers,
         *    respectively).
         *  - At each iteration we need two extra fp buffer (N fp values),
         *    and produce a k (N 32-bit words). k will be shared with one
         *    of the fp buffers.
         *  - To compute k*f and k*g efficiently (with the NTT), we need
         *    some extra room; we reuse the space of the temporary buffers.
         *
         * Arrays of 'fpr' are obtained from the temporary array itself.
         * We ensure that the base is at a properly aligned offset (the
         * source array tmp[] is supposed to be already aligned).
         */
        rt1 = new FalconFPR[n];
        rt2 = new FalconFPR[n];
        rt3 = new FalconFPR[n];
        rt4 = new FalconFPR[n];
        rt5 = new FalconFPR[n >> 1];
        k = new int[n];

        /*
         * Get f and g into rt3 and rt4 as floating-point approximations.
         *
         * We need to "scale down" the floating-point representation of
         * coefficients when they are too big. We want to keep the value
         * below 2^310 or so. Thus, when values are larger than 10 words,
         * we consider only the top 10 words. Array lengths have been
         * computed so that average maximum length will fall in the
         * middle or the upper half of these top 10 words.
         */
        rlen = (slen > 10) ? 10 : slen;
        poly_big_to_fp(rt3, 0, srctmp, ft + slen - rlen, rlen, slen, logn);
        poly_big_to_fp(rt4, 0, srctmp, gt + slen - rlen, rlen, slen, logn);

        /*
         * Values in rt3 and rt4 are downscaled by 2^(scale_fg).
         */
        scale_fg = 31 * (slen - rlen);

        /*
         * Estimated boundaries for the maximum size (in bits) of the
         * coefficients of (f,g). We use the measured average, and
         * allow for a deviation of at most six times the standard
         * deviation.
         */
        minbl_fg = bitlength_avg[depth] - 6 * bitlength_std[depth];
        maxbl_fg = bitlength_avg[depth] + 6 * bitlength_std[depth];

        /*
         * Compute 1/(f*adj(f)+g*adj(g)) in rt5. We also keep adj(f)
         * and adj(g) in rt3 and rt4, respectively.
         */
        fft.FFT(rt3, 0, logn);
        fft.FFT(rt4, 0, logn);
        fft.poly_invnorm2_fft(rt5, 0, rt3, 0, rt4, 0, logn);
        fft.poly_adj_fft(rt3, 0, logn);
        fft.poly_adj_fft(rt4, 0, logn);

        /*
         * Reduce F and G repeatedly.
         *
         * The expected maximum bit length of coefficients of F and G
         * is kept in maxbl_FG, with the corresponding word length in
         * FGlen.
         */
        FGlen = llen;
        maxbl_FG = 31 * llen;

        /*
         * Each reduction operation computes the reduction polynomial
         * "k". We need that polynomial to have coefficients that fit
         * on 32-bit signed integers, with some scaling; thus, we use
         * a descending sequence of scaling values, down to zero.
         *
         * The size of the coefficients of k is (roughly) the difference
         * between the size of the coefficients of (F,G) and the size
         * of the coefficients of (f,g). Thus, the maximum size of the
         * coefficients of k is, at the start, maxbl_FG - minbl_fg;
         * this is our starting scale value for k.
         *
         * We need to estimate the size of (F,G) during the execution of
         * the algorithm; we are allowed some overestimation but not too
         * much (poly_big_to_fp() uses a 310-bit window). Generally
         * speaking, after applying a reduction with k scaled to
         * scale_k, the size of (F,G) will be size(f,g) + scale_k + dd,
         * where 'dd' is a few bits to account for the fact that the
         * reduction is never perfect (intuitively, dd is on the order
         * of sqrt(N), so at most 5 bits; we here allow for 10 extra
         * bits).
         *
         * The size of (f,g) is not known exactly, but maxbl_fg is an
         * upper bound.
         */
        scale_k = maxbl_FG - minbl_fg;

        for (; ; )
        {
            int scale_FG, dc, new_maxbl_FG;
            int scl, sch;
            FalconFPR pdc, pt;

            /*
             * Convert current F and G into floating-point. We apply
             * scaling if the current length is more than 10 words.
             */
            rlen = (FGlen > 10) ? 10 : FGlen;
            scale_FG = 31 * (int)(FGlen - rlen);
            poly_big_to_fp(rt1, 0, srctmp, Ft + FGlen - rlen, rlen, llen, logn);
            poly_big_to_fp(rt2, 0, srctmp, Gt + FGlen - rlen, rlen, llen, logn);

            /*
             * Compute (F*adj(f)+G*adj(g))/(f*adj(f)+g*adj(g)) in rt2.
             */
            fft.FFT(rt1, 0, logn);
            fft.FFT(rt2, 0, logn);
            fft.poly_mul_fft(rt1, 0, rt3, 0, logn);
            fft.poly_mul_fft(rt2, 0, rt4, 0, logn);
            fft.poly_add(rt2, 0, rt1, 0, logn);
            fft.poly_mul_autoadj_fft(rt2, 0, rt5, 0, logn);
            fft.iFFT(rt2, 0, logn);

            /*
             * (f,g) are scaled by 'scale_fg', meaning that the
             * numbers in rt3/rt4 should be multiplied by 2^(scale_fg)
             * to have their true mathematical value.
             *
             * (F,G) are similarly scaled by 'scale_FG'. Therefore,
             * the value we computed in rt2 is scaled by
             * 'scale_FG-scale_fg'.
             *
             * We want that value to be scaled by 'scale_k', hence we
             * apply a corrective scaling. After scaling, the values
             * should fit in -2^31-1..+2^31-1.
             */
            dc = scale_k - scale_FG + scale_fg;

            /*
             * We will need to multiply values by 2^(-dc). The value
             * 'dc' is not secret, so we can compute 2^(-dc) with a
             * non-constant-time process.
             * (We could use ldexp(), but we prefer to avoid any
             * dependency on libm. When using FP emulation, we could
             * use our fpr_ldexp(), which is constant-time.)
             */
            if (dc < 0)
            {
                dc = -dc;
                pt = fpr.fpr_two;
            }
            else
            {
                pt = fpr.fpr_onehalf;
            }
            pdc = fpr.fpr_one;
            while (dc != 0)
            {
                if ((dc & 1) != 0)
                {
                    pdc = fpr.fpr_mul(pdc, pt);
                }
                dc >>= 1;
                pt = fpr.fpr_sqr(pt);
            }

            for (u = 0; u < n; u++)
            {
                FalconFPR xv;

                xv = fpr.fpr_mul(rt2[u], pdc);

                /*
                 * Sometimes the values can be out-of-bounds if
                 * the algorithm fails; we must not call
                 * fpr_rint() (and cast to int32_t) if the value
                 * is not in-bounds. Note that the test does not
                 * break constant-time discipline, since any
                 * failure here implies that we discard the current
                 * secret key (f,g).
                 */
                if (!fpr.fpr_lt(fpr.fpr_mtwo31m1, xv)
                    || !fpr.fpr_lt(xv, fpr.fpr_ptwo31m1))
                {
                    return 0;
                }
                k[u] = (int)fpr.fpr_rint(xv);
            }

            /*
             * Values in k[] are integers. They really are scaled
             * down by maxbl_FG - minbl_fg bits.
             *
             * If we are at low depth, then we use the NTT to
             * compute k*f and k*g.
             */
            sch = (scale_k / 31);
            scl = (scale_k % 31);
            if (depth <= DEPTH_INT_FG)
            {
                poly_sub_scaled_ntt(srctmp, Ft, FGlen, llen, srctmp, ft, slen, slen,
                    k, 0, sch, scl, logn, srctmp, t1);
                poly_sub_scaled_ntt(srctmp, Gt, FGlen, llen, srctmp, gt, slen, slen,
                    k, 0, sch, scl, logn, srctmp, t1);
            }
            else
            {
                poly_sub_scaled(srctmp, Ft, FGlen, llen, srctmp, ft, slen, slen,
                    k, 0, sch, scl, logn);
                poly_sub_scaled(srctmp, Gt, FGlen, llen, srctmp, gt, slen, slen,
                    k, 0, sch, scl, logn);
            }

            /*
             * We compute the new maximum size of (F,G), assuming that
             * (f,g) has _maximal_ length (i.e. that reduction is
             * "late" instead of "early". We also adjust FGlen
             * accordingly.
             */
            new_maxbl_FG = scale_k + maxbl_fg + 10;
            if (new_maxbl_FG < maxbl_FG)
            {
                maxbl_FG = new_maxbl_FG;
                if (FGlen * 31 >= maxbl_FG + 31)
                {
                    FGlen--;
                }
            }

            /*
             * We suppose that scaling down achieves a reduction by
             * at least 25 bits per iteration. We stop when we have
             * done the loop with an unscaled k.
             */
            if (scale_k <= 0)
            {
                break;
            }
            scale_k -= 25;
            if (scale_k < 0)
            {
                scale_k = 0;
            }
        }

        /*
         * If (F,G) length was lowered below 'slen', then we must take
         * care to re-extend the sign.
         */
        if (FGlen < slen)
        {
            for (u = 0; u < n; u++, Ft += llen, Gt += llen)
            {
                int v;
                int sw;

                sw = -(srctmp[Ft + FGlen - 1] >>> 30) >>> 1;
                for (v = FGlen; v < slen; v++)
                {
                    srctmp[Ft + v] = sw;
                }
                sw = -(srctmp[Gt + FGlen - 1] >>> 30) >>> 1;
                for (v = FGlen; v < slen; v++)
                {
                    srctmp[Gt + v] = sw;
                }
            }
        }

        /*
         * Compress encoding of all values to 'slen' words (this is the
         * expected output format).
         */
        for (u = 0, x = tmp, y = tmp;
             u < (n << 1); u++, x += slen, y += llen)
        {
//            memmove(x, y, slen * sizeof *y);
            System.arraycopy(srctmp, y, srctmp, x, slen);
        }
        return 1;
    }

    /*
     * Solving the NTRU equation, binary case, depth = 1. Upon entry, the
     * F and G from the previous level should be in the tmp[] array.
     *
     * Returned value: 1 on success, 0 on error.
     */
    int solve_NTRU_binary_depth1(int logn_top,
                                 byte[] srcf, int f, byte[] srcg, int g, int[] srctmp, int tmp)
    {
        /*
         * The first half of this function is a copy of the corresponding
         * part in solve_NTRU_intermediate(), for the reconstruction of
         * the unreduced F and G. The second half (Babai reduction) is
         * done differently, because the unreduced F and G fit in 53 bits
         * of precision, allowing a much simpler process with lower RAM
         * usage.
         */
        int depth, logn;
        int n_top, n, hn, slen, dlen, llen, u;
        int Fd, Gd, Ft, Gt, ft, gt, t1;
        FalconFPR[] rt1, rt2, rt3, rt4, rt5, rt6;
        int x, y;

        depth = 1;
        n_top = 1 << logn_top;
        logn = logn_top - depth;
        n = 1 << logn;
        hn = n >> 1;

        /*
         * Equations are:
         *
         *   f' = f0^2 - X^2*f1^2
         *   g' = g0^2 - X^2*g1^2
         *   F' and G' are a solution to f'G' - g'F' = q (from deeper levels)
         *   F = F'*(g0 - X*g1)
         *   G = G'*(f0 - X*f1)
         *
         * f0, f1, g0, g1, f', g', F' and G' are all "compressed" to
         * degree N/2 (their odd-indexed coefficients are all zero).
         */

        /*
         * slen = size for our input f and g; also size of the reduced
         *        F and G we return (degree N)
         *
         * dlen = size of the F and G obtained from the deeper level
         *        (degree N/2)
         *
         * llen = size for intermediary F and G before reduction (degree N)
         *
         * We build our non-reduced F and G as two independent halves each,
         * of degree N/2 (F = F0 + X*F1, G = G0 + X*G1).
         */
        slen = MAX_BL_SMALL[depth];
        dlen = MAX_BL_SMALL[depth + 1];
        llen = MAX_BL_LARGE[depth];

        /*
         * Fd and Gd are the F and G from the deeper level. Ft and Gt
         * are the destination arrays for the unreduced F and G.
         */
        Fd = tmp;
        Gd = Fd + dlen * hn;
        Ft = Gd + dlen * hn;
        Gt = Ft + llen * n;

        /*
         * We reduce Fd and Gd modulo all the small primes we will need,
         * and store the values in Ft and Gt.
         */
        for (u = 0; u < llen; u++)
        {
            int p, p0i, R2, Rx;
            int v;
            int xs, ys, xd, yd;

            p = this.primes.PRIMES[u].p;
            p0i = modp_ninv31(p);
            R2 = modp_R2(p, p0i);
            Rx = modp_Rx(dlen, p, p0i, R2);
            for (v = 0, xs = Fd, ys = Gd, xd = Ft + u, yd = Gt + u;
                 v < hn;
                 v++, xs += dlen, ys += dlen, xd += llen, yd += llen)
            {
                srctmp[xd] = zint_mod_small_signed(srctmp, xs, dlen, p, p0i, R2, Rx);
                srctmp[yd] = zint_mod_small_signed(srctmp, ys, dlen, p, p0i, R2, Rx);
            }
        }

        /*
         * Now Fd and Gd are not needed anymore; we can squeeze them out.
         */
//        memmove(tmp, Ft, llen * n * sizeof(uint32_t));
        System.arraycopy(srctmp, Ft, srctmp, tmp, llen * n);
        Ft = tmp;
//        memmove(Ft + llen * n, Gt, llen * n * sizeof(uint32_t));
        System.arraycopy(srctmp, Gt, srctmp, Ft + llen * n, llen * n);
        Gt = Ft + llen * n;
        ft = Gt + llen * n;
        gt = ft + slen * n;

        t1 = gt + slen * n;

        /*
         * Compute our F and G modulo sufficiently many small primes.
         */
        for (u = 0; u < llen; u++)
        {
            int p, p0i, R2;
            int gm, igm, fx, gx, Fp, Gp;
            int e;
            int v;

            /*
             * All computations are done modulo p.
             */
            p = this.primes.PRIMES[u].p;
            p0i = modp_ninv31(p);
            R2 = modp_R2(p, p0i);

            /*
             * We recompute things from the source f and g, of full
             * degree. However, we will need only the n first elements
             * of the inverse NTT table (igm); the call to modp_mkgm()
             * below will fill n_top elements in igm[] (thus overflowing
             * into fx[]) but later code will overwrite these extra
             * elements.
             */
            gm = t1;
            igm = gm + n_top;
            fx = igm + n;
            gx = fx + n_top;
            modp_mkgm2(srctmp, gm, srctmp, igm, logn_top, this.primes.PRIMES[u].g, p, p0i);

            /*
             * Set ft and gt to f and g modulo p, respectively.
             */
            for (v = 0; v < n_top; v++)
            {
                srctmp[fx + v] = modp_set(srcf[f + v], p);
                srctmp[gx + v] = modp_set(srcg[g + v], p);
            }

            /*
             * Convert to NTT and compute our f and g.
             */
            modp_NTT2(srctmp, fx, srctmp, gm, logn_top, p, p0i);
            modp_NTT2(srctmp, gx, srctmp, gm, logn_top, p, p0i);
            for (e = logn_top; e > logn; e--)
            {
                modp_poly_rec_res(srctmp, fx, e, p, p0i, R2);
                modp_poly_rec_res(srctmp, gx, e, p, p0i, R2);
            }

            /*
             * From that point onward, we only need tables for
             * degree n, so we can save some space.
             */
            if (depth > 0)
            { /* always true */
//                memmove(gm + n, igm, n * sizeof *igm);
                System.arraycopy(srctmp, igm, srctmp, gm + n, n);
                igm = gm + n;
//                memmove(igm + n, fx, n * sizeof *ft);
                System.arraycopy(srctmp, fx, srctmp, igm + n, n);
                fx = igm + n;
//                memmove(fx + n, gx, n * sizeof *gt);
                System.arraycopy(srctmp, gx, srctmp, fx + n, n);
                gx = fx + n;
            }

            /*
             * Get F' and G' modulo p and in NTT representation
             * (they have degree n/2). These values were computed
             * in a previous step, and stored in Ft and Gt.
             */
            Fp = gx + n;
            Gp = Fp + hn;
            for (v = 0, x = Ft + u, y = Gt + u;
                 v < hn; v++, x += llen, y += llen)
            {
                srctmp[Fp + v] = srctmp[x];
                srctmp[Gp + v] = srctmp[y];
            }
            modp_NTT2(srctmp, Fp, srctmp, gm, logn - 1, p, p0i);
            modp_NTT2(srctmp, Gp, srctmp, gm, logn - 1, p, p0i);

            /*
             * Compute our F and G modulo p.
             *
             * Equations are:
             *
             *   f'(x^2) = N(f)(x^2) = f * adj(f)
             *   g'(x^2) = N(g)(x^2) = g * adj(g)
             *
             *   f'*G' - g'*F' = q
             *
             *   F = F'(x^2) * adj(g)
             *   G = G'(x^2) * adj(f)
             *
             * The NTT representation of f is f(w) for all w which
             * are roots of phi. In the binary case, as well as in
             * the ternary case for all depth except the deepest,
             * these roots can be grouped in pairs (w,-w), and we
             * then have:
             *
             *   f(w) = adj(f)(-w)
             *   f(-w) = adj(f)(w)
             *
             * and w^2 is then a root for phi at the half-degree.
             *
             * At the deepest level in the ternary case, this still
             * holds, in the following sense: the roots of x^2-x+1
             * are (w,-w^2) (for w^3 = -1, and w != -1), and we
             * have:
             *
             *   f(w) = adj(f)(-w^2)
             *   f(-w^2) = adj(f)(w)
             *
             * In all case, we can thus compute F and G in NTT
             * representation by a few simple multiplications.
             * Moreover, the two roots for each pair are consecutive
             * in our bit-reversal encoding.
             */
            for (v = 0, x = Ft + u, y = Gt + u;
                 v < hn; v++, x += (llen << 1), y += (llen << 1))
            {
                int ftA, ftB, gtA, gtB;
                int mFp, mGp;

                ftA = srctmp[fx + (v << 1) + 0];
                ftB = srctmp[fx + (v << 1) + 1];
                gtA = srctmp[gx + (v << 1) + 0];
                gtB = srctmp[gx + (v << 1) + 1];
                mFp = modp_montymul(srctmp[Fp + v], R2, p, p0i);
                mGp = modp_montymul(srctmp[Gp + v], R2, p, p0i);
                srctmp[x + 0] = modp_montymul(gtB, mFp, p, p0i);
                srctmp[x + llen] = modp_montymul(gtA, mFp, p, p0i);
                srctmp[y + 0] = modp_montymul(ftB, mGp, p, p0i);
                srctmp[y + llen] = modp_montymul(ftA, mGp, p, p0i);
            }
            modp_iNTT2_ext(srctmp, Ft + u, llen, srctmp, igm, logn, p, p0i);
            modp_iNTT2_ext(srctmp, Gt + u, llen, srctmp, igm, logn, p, p0i);

            /*
             * Also save ft and gt (only up to size slen).
             */
            if (u < slen)
            {
                modp_iNTT2(srctmp, fx, srctmp, igm, logn, p, p0i);
                modp_iNTT2(srctmp, gx, srctmp, igm, logn, p, p0i);
                for (v = 0, x = ft + u, y = gt + u;
                     v < n; v++, x += slen, y += slen)
                {
                    srctmp[x] = srctmp[fx + v];
                    srctmp[y] = srctmp[gx + v];
                }
            }
        }

        /*
         * Rebuild f, g, F and G with the CRT. Note that the elements of F
         * and G are consecutive, and thus can be rebuilt in a single
         * loop; similarly, the elements of f and g are consecutive.
         */
        zint_rebuild_CRT(srctmp, Ft, llen, llen, n << 1, this.primes.PRIMES, 1, srctmp, t1);
        zint_rebuild_CRT(srctmp, ft, slen, slen, n << 1, this.primes.PRIMES, 1, srctmp, t1);

        /*
         * Here starts the Babai reduction, specialized for depth = 1.
         *
         * Candidates F and G (from Ft and Gt), and base f and g (ft and gt),
         * are converted to floating point. There is no scaling, and a
         * single pass is sufficient.
         */

        /*
         * Convert F and G into floating point (rt1 and rt2).
         */
//        rt1 = align_fpr(tmp, gt + slen * n);
        rt1 = new FalconFPR[n];
        rt2 = new FalconFPR[n];
        poly_big_to_fp(rt1, 0, srctmp, Ft, llen, llen, logn);
        poly_big_to_fp(rt2, 0, srctmp, Gt, llen, llen, logn);

        /*
         * Integer representation of F and G is no longer needed, we
         * can remove it.
         */
//        memmove(tmp, ft, 2 * slen * n * sizeof *ft);
        System.arraycopy(srctmp, ft, srctmp, tmp, 2 * slen * n);
        ft = tmp;
        gt = ft + slen * n;
//        rt3 = align_fpr(tmp, gt + slen * n);
//        memmove(rt3, rt1, 2 * n * sizeof *rt1);
//        rt1 = rt3;
//        rt2 = rt1 + n;
        rt3 = new FalconFPR[n];
        rt4 = new FalconFPR[n];

        /*
         * Convert f and g into floating point (rt3 and rt4).
         */
        poly_big_to_fp(rt3, 0, srctmp, ft, slen, slen, logn);
        poly_big_to_fp(rt4, 0, srctmp, gt, slen, slen, logn);

        /*
         * Remove unneeded ft and gt. - not required as we have rt_ in separate array
         */
//        memmove(tmp, rt1, 4 * n * sizeof *rt1);
//        rt1 = (fpr *)tmp;
//        rt2 = rt1 + n;
//        rt3 = rt2 + n;
//        rt4 = rt3 + n;

        /*
         * We now have:
         *   rt1 = F
         *   rt2 = G
         *   rt3 = f
         *   rt4 = g
         * in that order in RAM. We convert all of them to FFT.
         */
        fft.FFT(rt1, 0, logn);
        fft.FFT(rt2, 0, logn);
        fft.FFT(rt3, 0, logn);
        fft.FFT(rt4, 0, logn);

        /*
         * Compute:
         *   rt5 = F*adj(f) + G*adj(g)
         *   rt6 = 1 / (f*adj(f) + g*adj(g))
         * (Note that rt6 is half-length.)
         */
        rt5 = new FalconFPR[n];
        rt6 = new FalconFPR[n >> 1];
        fft.poly_add_muladj_fft(rt5, 0, rt1, 0, rt2, 0, rt3, 0, rt4, 0, logn);
        fft.poly_invnorm2_fft(rt6, 0, rt3, 0, rt4, 0, logn);

        /*
         * Compute:
         *   rt5 = (F*adj(f)+G*adj(g)) / (f*adj(f)+g*adj(g))
         */
        fft.poly_mul_autoadj_fft(rt5, 0, rt6, 0, logn);

        /*
         * Compute k as the rounded version of rt5. Check that none of
         * the values is larger than 2^63-1 (in absolute value)
         * because that would make the fpr_rint() do something undefined;
         * note that any out-of-bounds value here implies a failure and
         * (f,g) will be discarded, so we can make a simple test.
         */
        fft.iFFT(rt5, 0, logn);
        for (u = 0; u < n; u++)
        {
            FalconFPR z;

            z = rt5[u];
            if (!fpr.fpr_lt(z, fpr.fpr_ptwo63m1) || !fpr.fpr_lt(fpr.fpr_mtwo63m1, z))
            {
                return 0;
            }
            rt5[u] = fpr.fpr_of(fpr.fpr_rint(z));
        }
        fft.FFT(rt5, 0, logn);

        /*
         * Subtract k*f from F, and k*g from G.
         */
        fft.poly_mul_fft(rt3, 0, rt5, 0, logn);
        fft.poly_mul_fft(rt4, 0, rt5, 0, logn);
        fft.poly_sub(rt1, 0, rt3, 0, logn);
        fft.poly_sub(rt2, 0, rt4, 0, logn);
        fft.iFFT(rt1, 0, logn);
        fft.iFFT(rt2, 0, logn);

        /*
         * Convert back F and G to integers, and return.
         */
        Ft = tmp;
        Gt = Ft + n;
//        rt3 = align_fpr(tmp, Gt + n);
//        memmove(rt3, rt1, 2 * n * sizeof *rt1);
//        rt1 = rt3;
//        rt2 = rt1 + n;
        for (u = 0; u < n; u++)
        {
            srctmp[Ft + u] = (int)fpr.fpr_rint(rt1[u]);
            srctmp[Gt + u] = (int)fpr.fpr_rint(rt2[u]);
        }

        return 1;
    }

    /*
     * Solving the NTRU equation, top level. Upon entry, the F and G
     * from the previous level should be in the tmp[] array.
     *
     * Returned value: 1 on success, 0 on error.
     */
    int solve_NTRU_binary_depth0(int logn,
                                 byte[] srcf, int f, byte[] srcg, int g, int[] srctmp, int tmp)
    {
        int n, hn, u;
        int p, p0i, R2;
        int Fp, Gp, t1, t2, t3, t4, t5;
        int gm, igm, ft, gt;
        int rt1, rt2, rt3;

        n = 1 << logn;
        hn = n >> 1;

        /*
         * Equations are:
         *
         *   f' = f0^2 - X^2*f1^2
         *   g' = g0^2 - X^2*g1^2
         *   F' and G' are a solution to f'G' - g'F' = q (from deeper levels)
         *   F = F'*(g0 - X*g1)
         *   G = G'*(f0 - X*f1)
         *
         * f0, f1, g0, g1, f', g', F' and G' are all "compressed" to
         * degree N/2 (their odd-indexed coefficients are all zero).
         *
         * Everything should fit in 31-bit integers, hence we can just use
         * the first small prime p = 2147473409.
         */
        p = this.primes.PRIMES[0].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);

        Fp = tmp;
        Gp = Fp + hn;
        ft = Gp + hn;
        gt = ft + n;
        gm = gt + n;
        igm = gm + n;

        modp_mkgm2(srctmp, gm, srctmp, igm, logn, this.primes.PRIMES[0].g, p, p0i);

        /*
         * Convert F' anf G' in NTT representation.
         */
        for (u = 0; u < hn; u++)
        {
            srctmp[Fp + u] = modp_set(zint_one_to_plain(srctmp, Fp + u), p);
            srctmp[Gp + u] = modp_set(zint_one_to_plain(srctmp, Gp + u), p);
        }
        modp_NTT2(srctmp, Fp, srctmp, gm, logn - 1, p, p0i);
        modp_NTT2(srctmp, Gp, srctmp, gm, logn - 1, p, p0i);

        /*
         * Load f and g and convert them to NTT representation.
         */
        for (u = 0; u < n; u++)
        {
            srctmp[ft + u] = modp_set(srcf[f + u], p);
            srctmp[gt + u] = modp_set(srcg[g + u], p);
        }
        modp_NTT2(srctmp, ft, srctmp, gm, logn, p, p0i);
        modp_NTT2(srctmp, gt, srctmp, gm, logn, p, p0i);

        /*
         * Build the unreduced F,G in ft and gt.
         */
        for (u = 0; u < n; u += 2)
        {
            int ftA, ftB, gtA, gtB;
            int mFp, mGp;

            ftA = srctmp[ft + u + 0];
            ftB = srctmp[ft + u + 1];
            gtA = srctmp[gt + u + 0];
            gtB = srctmp[gt + u + 1];
            mFp = modp_montymul(srctmp[Fp + (u >> 1)], R2, p, p0i);
            mGp = modp_montymul(srctmp[Gp + (u >> 1)], R2, p, p0i);
            srctmp[ft + u + 0] = modp_montymul(gtB, mFp, p, p0i);
            srctmp[ft + u + 1] = modp_montymul(gtA, mFp, p, p0i);
            srctmp[gt + u + 0] = modp_montymul(ftB, mGp, p, p0i);
            srctmp[gt + u + 1] = modp_montymul(ftA, mGp, p, p0i);
        }
        modp_iNTT2(srctmp, ft, srctmp, igm, logn, p, p0i);
        modp_iNTT2(srctmp, gt, srctmp, igm, logn, p, p0i);

        Gp = Fp + n;
        t1 = Gp + n;
//        memmove(Fp, ft, 2 * n * sizeof *ft);
        System.arraycopy(srctmp, ft, srctmp, Fp, 2 * n);

        /*
         * We now need to apply the Babai reduction. At that point,
         * we have F and G in two n-word arrays.
         *
         * We can compute F*adj(f)+G*adj(g) and f*adj(f)+g*adj(g)
         * modulo p, using the NTT. We still move memory around in
         * order to save RAM.
         */
        t2 = t1 + n;
        t3 = t2 + n;
        t4 = t3 + n;
        t5 = t4 + n;

        /*
         * Compute the NTT tables in t1 and t2. We do not keep t2
         * (we'll recompute it later on).
         */
        modp_mkgm2(srctmp, t1, srctmp, t2, logn, this.primes.PRIMES[0].g, p, p0i);

        /*
         * Convert F and G to NTT.
         */
        modp_NTT2(srctmp, Fp, srctmp, t1, logn, p, p0i);
        modp_NTT2(srctmp, Gp, srctmp, t1, logn, p, p0i);

        /*
         * Load f and adj(f) in t4 and t5, and convert them to NTT
         * representation.
         */
        srctmp[t4 + 0] = srctmp[t5 + 0] = modp_set(srcf[f + 0], p);
        for (u = 1; u < n; u++)
        {
            srctmp[t4 + u] = modp_set(srcf[f + u], p);
            srctmp[t5 + n - u] = modp_set(-srcf[f + u], p);
        }
        modp_NTT2(srctmp, t4, srctmp, t1, logn, p, p0i);
        modp_NTT2(srctmp, t5, srctmp, t1, logn, p, p0i);

        /*
         * Compute F*adj(f) in t2, and f*adj(f) in t3.
         */
        for (u = 0; u < n; u++)
        {
            int w;

            w = modp_montymul(srctmp[t5 + u], R2, p, p0i);
            srctmp[t2 + u] = modp_montymul(w, srctmp[Fp + u], p, p0i);
            srctmp[t3 + u] = modp_montymul(w, srctmp[t4 + u], p, p0i);
        }

        /*
         * Load g and adj(g) in t4 and t5, and convert them to NTT
         * representation.
         */
        srctmp[t4 + 0] = srctmp[t5 + 0] = modp_set(srcg[g + 0], p);
        for (u = 1; u < n; u++)
        {
            srctmp[t4 + u] = modp_set(srcg[g + u], p);
            srctmp[t5 + n - u] = modp_set(-srcg[g + u], p);
        }
        modp_NTT2(srctmp, t4, srctmp, t1, logn, p, p0i);
        modp_NTT2(srctmp, t5, srctmp, t1, logn, p, p0i);

        /*
         * Add G*adj(g) to t2, and g*adj(g) to t3.
         */
        for (u = 0; u < n; u++)
        {
            int w;

            w = modp_montymul(srctmp[t5 + u], R2, p, p0i);
            srctmp[t2 + u] = modp_add(srctmp[t2 + u],
                modp_montymul(w, srctmp[Gp + u], p, p0i), p);
            srctmp[t3 + u] = modp_add(srctmp[t3 + u],
                modp_montymul(w, srctmp[t4 + u], p, p0i), p);
        }

        /*
         * Convert back t2 and t3 to normal representation (normalized
         * around 0), and then
         * move them to t1 and t2. We first need to recompute the
         * inverse table for NTT.
         */
        modp_mkgm2(srctmp, t1, srctmp, t4, logn, this.primes.PRIMES[0].g, p, p0i);
        modp_iNTT2(srctmp, t2, srctmp, t4, logn, p, p0i);
        modp_iNTT2(srctmp, t3, srctmp, t4, logn, p, p0i); // TODO fix binary_depth0 -> t1 value is wrong
        for (u = 0; u < n; u++)
        {
            srctmp[t1 + u] = modp_norm(srctmp[t2 + u], p);
            srctmp[t2 + u] = modp_norm(srctmp[t3 + u], p);
        }

        /*
         * At that point, array contents are:
         *
         *   F (NTT representation) (Fp)
         *   G (NTT representation) (Gp)
         *   F*adj(f)+G*adj(g) (t1)
         *   f*adj(f)+g*adj(g) (t2)
         *
         * We want to divide t1 by t2. The result is not integral; it
         * must be rounded. We thus need to use the FFT.
         */

        /*
         * Get f*adj(f)+g*adj(g) in FFT representation. Since this
         * polynomial is auto-adjoint, all its coordinates in FFT
         * representation are actually real, so we can truncate off
         * the imaginary parts.
         */
        FalconFPR[]
            tmp2 = new FalconFPR[3 * n];
//        rt3 = align_fpr(tmp, t3);
        rt1 = 0;
        rt2 = rt1 + n;
        rt3 = rt2 + n;
        for (u = 0; u < n; u++)
        {
            tmp2[rt3 + u] = fpr.fpr_of(srctmp[t2 + u]);
        }
        fft.FFT(tmp2, rt3, logn);
//        rt2 = align_fpr(tmp, t2);
//        memmove(rt2, rt3, hn * sizeof *rt3);
        System.arraycopy(tmp2, rt3, tmp2, rt2, hn);

        /*
         * Convert F*adj(f)+G*adj(g) in FFT representation.
         */
        rt3 = rt2 + hn;
        for (u = 0; u < n; u++)
        {
            tmp2[rt3 + u] = fpr.fpr_of(srctmp[t1 + u]);
        }
        fft.FFT(tmp2, rt3, logn);

        /*
         * Compute (F*adj(f)+G*adj(g))/(f*adj(f)+g*adj(g)) and get
         * its rounded normal representation in t1.
         */
        fft.poly_div_autoadj_fft(tmp2, rt3, tmp2, rt2, logn);
        fft.iFFT(tmp2, rt3, logn);
        for (u = 0; u < n; u++)
        {
            srctmp[t1 + u] = modp_set((int)fpr.fpr_rint(tmp2[rt3 + u]), p);
        }

        /*
         * RAM contents are now:
         *
         *   F (NTT representation) (Fp)
         *   G (NTT representation) (Gp)
         *   k (t1)
         *
         * We want to compute F-k*f, and G-k*g.
         */
        t2 = t1 + n;
        t3 = t2 + n;
        t4 = t3 + n;
        t5 = t4 + n;
        modp_mkgm2(srctmp, t2, srctmp, t3, logn, this.primes.PRIMES[0].g, p, p0i);
        for (u = 0; u < n; u++)
        {
            srctmp[t4 + u] = modp_set(srcf[f + u], p);
            srctmp[t5 + u] = modp_set(srcg[g + u], p);
        }
        modp_NTT2(srctmp, t1, srctmp, t2, logn, p, p0i);
        modp_NTT2(srctmp, t4, srctmp, t2, logn, p, p0i);
        modp_NTT2(srctmp, t5, srctmp, t2, logn, p, p0i);
        for (u = 0; u < n; u++)
        {
            int kw;

            kw = modp_montymul(srctmp[t1 + u], R2, p, p0i);
            srctmp[Fp + u] = modp_sub(srctmp[Fp + u],
                modp_montymul(kw, srctmp[t4 + u], p, p0i), p);
            srctmp[Gp + u] = modp_sub(srctmp[Gp + u],
                modp_montymul(kw, srctmp[t5 + u], p, p0i), p);
        }
        modp_iNTT2(srctmp, Fp, srctmp, t3, logn, p, p0i);
        modp_iNTT2(srctmp, Gp, srctmp, t3, logn, p, p0i);
        for (u = 0; u < n; u++)
        {
            srctmp[Fp + u] = modp_norm(srctmp[Fp + u], p);
            srctmp[Gp + u] = modp_norm(srctmp[Gp + u], p);
        }

        return 1;
    }

    /*
     * Solve the NTRU equation. Returned value is 1 on success, 0 on error.
     * G can be NULL, in which case that value is computed but not returned.
     * If any of the coefficients of F and G exceeds lim (in absolute value),
     * then 0 is returned.
     */
    int solve_NTRU(int logn, byte[] srcF, int F, byte[] srcG, int G,
                   byte[] srcf, int f, byte[] srcg, int g, int lim, int[] srctmp, int tmp)
    {
        int n, u;
        int ft, gt, Ft, Gt, gm;
        int p, p0i, r;
        FalconSmallPrime[] primes;

        n = mkn(logn);

        if (solve_NTRU_deepest(logn, srcf, f, srcg, g, srctmp, tmp) == 0)
        {
            return 0;
        }

        /*
         * For logn <= 2, we need to use solve_NTRU_intermediate()
         * directly, because coefficients are a bit too large and
         * do not fit the hypotheses in solve_NTRU_binary_depth0().
         */
        if (logn <= 2)
        {
            int depth;

            depth = logn;
            while (depth-- > 0)
            {
                if (solve_NTRU_intermediate(logn, srcf, f, srcg, g, depth, srctmp, tmp) == 0)
                {
                    return 0;
                }
            }
        }
        else
        {
            int depth;

            depth = logn;
            while (depth-- > 2)
            {
                if (solve_NTRU_intermediate(logn, srcf, f, srcg, g, depth, srctmp, tmp) == 0)
                {
                    return 0;
                }
            }
            if (solve_NTRU_binary_depth1(logn, srcf, f, srcg, g, srctmp, tmp) == 0)
            {
                return 0;
            }
            if (solve_NTRU_binary_depth0(logn, srcf, f, srcg, g, srctmp, tmp) == 0)
            {
                return 0;
            }
        }

        /*
         * If no buffer has been provided for G, use a temporary one.
         */
        if (srcG == null)
        {
            G = 0;
            srcG = new byte[n];
        }

        /*
         * Final F and G are in fk->tmp, one word per coefficient
         * (signed value over 31 bits).
         */
        if (poly_big_to_small(srcF, F, srctmp, tmp, lim, logn) == 0
            || poly_big_to_small(srcG, G, srctmp, tmp + n, lim, logn) == 0)
        {
            return 0;
        }

        /*
         * Verify that the NTRU equation is fulfilled. Since all elements
         * have short lengths, verifying modulo a small prime p works, and
         * allows using the NTT.
         *
         * We put Gt[] first in tmp[], and process it first, so that it does
         * not overlap with G[] in case we allocated it ourselves.
         */
        Gt = tmp;
        ft = Gt + n;
        gt = ft + n;
        Ft = gt + n;
        gm = Ft + n;

        primes = this.primes.PRIMES;
        p = primes[0].p;
        p0i = modp_ninv31(p);
        modp_mkgm2(srctmp, gm, srctmp, tmp, logn, primes[0].g, p, p0i);
        for (u = 0; u < n; u++)
        {
            srctmp[Gt + u] = modp_set(srcG[G + u], p);
        }
        for (u = 0; u < n; u++)
        {
            srctmp[ft + u] = modp_set(srcf[f + u], p);
            srctmp[gt + u] = modp_set(srcg[g + u], p);
            srctmp[Ft + u] = modp_set(srcF[F + u], p);
        }
        modp_NTT2(srctmp, ft, srctmp, gm, logn, p, p0i);
        modp_NTT2(srctmp, gt, srctmp, gm, logn, p, p0i);
        modp_NTT2(srctmp, Ft, srctmp, gm, logn, p, p0i);
        modp_NTT2(srctmp, Gt, srctmp, gm, logn, p, p0i);
        r = modp_montymul(12289, 1, p, p0i);
        for (u = 0; u < n; u++)
        {
            int z;

            z = modp_sub(modp_montymul(srctmp[ft + u], srctmp[Gt + u], p, p0i),
                modp_montymul(srctmp[gt + u], srctmp[Ft + u], p, p0i), p);
            if (z != r)
            {
                return 0;
            }
        }

        return 1;
    }

    /*
     * Generate a random polynomial with a Gaussian distribution. This function
     * also makes sure that the resultant of the polynomial with phi is odd.
     */
    void poly_small_mkgauss(SHAKE256 rng, byte[] srcf, int f, int logn)
    {
        int n, u;
        int mod2;

        n = mkn(logn);
        mod2 = 0;
        for (u = 0; u < n; u++)
        {
            int s;

            for (; ; )
            {
                s = mkgauss(rng, logn);

                /*
                 * We need the coefficient to fit within -127..+127;
                 * realistically, this is always the case except for
                 * the very low degrees (N = 2 or 4), for which there
                 * is no real security anyway.
                 */
                if (s < -127 || s > 127)
                {
                    continue;
                }

                /*
                 * We need the sum of all coefficients to be 1; otherwise,
                 * the resultant of the polynomial with X^N+1 will be even,
                 * and the binary GCD will fail.
                 */
                if (u == n - 1)
                {
                    if ((mod2 ^ (s & 1)) == 0)
                    {
                        continue;
                    }
                }
                else
                {
                    mod2 ^= (s & 1);
                }
                srcf[f + u] = (byte)s;
                break;
            }
        }
    }

    /* see falcon.h */
    void keygen(SHAKE256 rng,
                byte[] srcf, int f, byte[] srcg, int g, byte[] srcF, int F, byte[] srcG, int G, short[] srch, int h,
                int logn)
    {
        /*
         * Algorithm is the following:
         *
         *  - Generate f and g with the Gaussian distribution.
         *
         *  - If either Res(f,phi) or Res(g,phi) is even, try again.
         *
         *  - If ||(f,g)|| is too large, try again.
         *
         *  - If ||B~_{f,g}|| is too large, try again.
         *
         *  - If f is not invertible mod phi mod q, try again.
         *
         *  - Compute h = g/f mod phi mod q.
         *
         *  - Solve the NTRU equation fG - gF = q; if the solving fails,
         *    try again. Usual failure condition is when Res(f,phi)
         *    and Res(g,phi) are not prime to each other.
         */
        int n, u;
        int[] itmp;
        byte[] btmp;
        short[] stmp;
        FalconFPR[] ftmp;
        int h2, tmp2;
        SHAKE256 rc;

        n = mkn(logn);
        rc = rng;

        /*
         * We need to generate f and g randomly, until we find values
         * such that the norm of (g,-f), and of the orthogonalized
         * vector, are satisfying. The orthogonalized vector is:
         *   (q*adj(f)/(f*adj(f)+g*adj(g)), q*adj(g)/(f*adj(f)+g*adj(g)))
         * (it is actually the (N+1)-th row of the Gram-Schmidt basis).
         *
         * In the binary case, coefficients of f and g are generated
         * independently of each other, with a discrete Gaussian
         * distribution of standard deviation 1.17*sqrt(q/(2*N)). Then,
         * the two vectors have expected norm 1.17*sqrt(q), which is
         * also our acceptance bound: we require both vectors to be no
         * larger than that (this will be satisfied about 1/4th of the
         * time, thus we expect sampling new (f,g) about 4 times for that
         * step).
         *
         * We require that Res(f,phi) and Res(g,phi) are both odd (the
         * NTRU equation solver requires it).
         */
        for (; ; )
        {
            ftmp = new FalconFPR[3 * n];
            int rt1, rt2, rt3;
            FalconFPR bnorm;
            int normf, normg, norm;
            int lim;

            /*
             * The poly_small_mkgauss() function makes sure
             * that the sum of coefficients is 1 modulo 2
             * (i.e. the resultant of the polynomial with phi
             * will be odd).
             */
            poly_small_mkgauss(rc, srcf, f, logn);
            poly_small_mkgauss(rc, srcg, g, logn);

            /*
             * Verify that all coefficients are within the bounds
             * defined in max_fg_bits. This is the case with
             * overwhelming probability; this guarantees that the
             * key will be encodable with FALCON_COMP_TRIM.
             */
            lim = 1 << (codec.max_fg_bits[logn] - 1);
            for (u = 0; u < n; u++)
            {
                /*
                 * We can use non-CT tests since on any failure
                 * we will discard f and g.
                 */
                if (srcf[f + u] >= lim || srcf[f + u] <= -lim
                    || srcg[g + u] >= lim || srcg[g + u] <= -lim)
                {
                    lim = -1;
                    break;
                }
            }
            if (lim < 0)
            {
                continue;
            }

            /*
             * Bound is 1.17*sqrt(q). We compute the squared
             * norms. With q = 12289, the squared bound is:
             *   (1.17^2)* 12289 = 16822.4121
             * Since f and g are integral, the squared norm
             * of (g,-f) is an integer.
             */
            normf = poly_small_sqnorm(srcf, f, logn);
            normg = poly_small_sqnorm(srcg, g, logn);
            norm = (normf + normg) | -((normf | normg) >>> 31);
            if ((norm & 0xffffffffL) >= 16823L)
            {
                continue;
            }

            /*
             * We compute the orthogonalized vector norm.
             */
            rt1 = 0;
            rt2 = rt1 + n;
            rt3 = rt2 + n;
            poly_small_to_fp(ftmp, rt1, srcf, f, logn);
            poly_small_to_fp(ftmp, rt2, srcg, g, logn);
            fft.FFT(ftmp, rt1, logn);
            fft.FFT(ftmp, rt2, logn);
            fft.poly_invnorm2_fft(ftmp, rt3, ftmp, rt1, ftmp, rt2, logn);
            fft.poly_adj_fft(ftmp, rt1, logn);
            fft.poly_adj_fft(ftmp, rt2, logn);
            fft.poly_mulconst(ftmp, rt1, fpr.fpr_q, logn);
            fft.poly_mulconst(ftmp, rt2, fpr.fpr_q, logn);
            fft.poly_mul_autoadj_fft(ftmp, rt1, ftmp, rt3, logn);
            fft.poly_mul_autoadj_fft(ftmp, rt2, ftmp, rt3, logn);
            fft.iFFT(ftmp, rt1, logn);
            fft.iFFT(ftmp, rt2, logn);
            bnorm = fpr.fpr_zero;
            for (u = 0; u < n; u++)
            {
                bnorm = fpr.fpr_add(bnorm, fpr.fpr_sqr(ftmp[rt1 + u]));
                bnorm = fpr.fpr_add(bnorm, fpr.fpr_sqr(ftmp[rt2 + u]));
            }
            if (!fpr.fpr_lt(bnorm, fpr.fpr_bnorm_max))
            {
                continue;
            }

            /*
             * Compute public key h = g/f mod X^N+1 mod q. If this
             * fails, we must restart.
             */
            stmp = new short[2 * n];
            if (srch == null)
            {
                h2 = 0;
                srch = stmp;
                tmp2 = h2 + n;
            }
            else
            {
                h2 = h;
                tmp2 = 0;
            }
            if (vrfy.compute_public(srch, h2, srcf, f, srcg, g, logn, stmp, tmp2) == 0)
            {
                continue;
            }

            /*
             * Solve the NTRU equation to get F and G.
             */
            itmp = logn > 2 ? new int[28 * n] : new int[28 * n * 3];
            lim = (1 << (codec.max_FG_bits[logn] - 1)) - 1;
            if (solve_NTRU(logn, srcF, F, srcG, G, srcf, f, srcg, g, lim, itmp, 0) == 0)
            {
                continue;
            }

            /*
             * Key pair is generated.
             */
            break;
        }
    }

    private long toUnsignedLong(int x)
    {
        return x & 0xffffffffL;
    }
}
