package org.bouncycastle.pqc.crypto.falcon;

class FalconCommon
{

    /**
     * montgomery multiplication in modulo p
     */
    static int modp_montymul(int a, int b, int p, int p0i)
    {
        long z, w;
        int d;

        z = FalconCommon.uint_long(a) * FalconCommon.uint_long(b);
        w = ((z * p0i) & (long)0x7FFFFFFF) * p;
        d = (int)((z + w) >>> 31) - p;
        d += p & -(d >>> 31);
        return d;
    }

    /**
     * addition in modulo p
     */
    static int modp_add(int a, int b, int p)
    {
        int d;
        d = a + b - p;
        d += p & -(d >>> 31);
        return d;
    }

    /**
     * subtraction in modulo p
     */
    static int modp_sub(int a, int b, int p)
    {
        int d;
        d = a - b;
        d += p & -(d >>> 31);
        return d;
    }

    /**
     * gets -1/p mod 2^31
     */
    static int modp_ninv31(int p)
    {
        int y;
        y = 2 - p;
        y *= 2 - p * y;
        y *= 2 - p * y;
        y *= 2 - p * y;
        y *= 2 - p * y;
        return 0x7FFFFFFF & -y;
    }

    /**
     * gets R = 2^31 modp
     */
    static int modp_R(int p)
    {
        return (1 << 31) - p;
    }

    /**
     * gets R2 = 2^62 modp
     */
    static int modp_R2(int p, int p0i)
    {
        int z;
        z = modp_R(p);
        z = modp_add(z, z, p);
        z = modp_montymul(z, z, p, p0i);
        z = modp_montymul(z, z, p, p0i);
        z = modp_montymul(z, z, p, p0i);
        z = modp_montymul(z, z, p, p0i);
        z = modp_montymul(z, z, p, p0i);
        z = (z + (p & -(z & 1))) >>> 1;
        return z;
    }

    static int modp_set(int x, int p)
    {
        int w;
        w = x;
        w += p & -(w >>> 31);
        return w;
    }

    static void modp_mkgm2(int gm, int igm, int[] data, int logn, int g_in, int p, int p0i)
    {
        int u, n;
        int k;
        int ig, x1, x2, R2;
        int g = g_in;

        n = 1 << logn;

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
            data[gm + v] = x1;
            data[igm + v] = x2;
            x1 = modp_montymul(x1, g, p, p0i);
            x2 = modp_montymul(x2, ig, p, p0i);
        }
    }

    private static int modp_div(int a, int b, int p, int p0i, int R)
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

    /**
     * converts a 2d array of num elements containing alen slots each into a 1d array
     */
    static int[] array_flatten(int[][] arrays, int alen, int num)
    {
        int[] res = new int[alen * num];
        int index = 0;
        for (int i = 0; i < num; i++)
        {
            for (int j = 0; j < alen; j++)
            {
                res[index] = arrays[i][j];
                index++;
            }
        }
        return res;
    }

    /**
     * cast unsigned int to long
     */
    static long uint_long(int x)
    {
        return Long.parseLong(Integer.toUnsignedString(x));
    }

    /*
     * Bit-reversal index table.
     */
    static final short[] REV10 = {
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

    static int modp_Rx(int x, int p, int p0i, int R2)
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

    static void modp_poly_rec_res(int f, int[] fdata, int logn, int p, int p0i, int R2)
    {
        int hn, u;

        hn = 1 << (logn - 1);
        for (u = 0; u < hn; u++)
        {
            int w0, w1;

            w0 = fdata[f + (u << 1) + 0];
            w1 = fdata[f + (u << 1) + 1];
            fdata[f + u] = modp_montymul(modp_montymul(w0, w1, p, p0i), R2, p, p0i);
        }
    }

    static int modp_norm(int x, int p)
    {
        return (int)(x - (p & (((x - ((p + 1) >>> 1)) >>> 31) - 1)));
    }

    // returns size of output in out_arr
    static int modq_encode(int out, byte[] out_arr, int outlenmax, int x, short[] x_arr, int logn)
    {
        int n, out_len, u;
        int buf;
        int acc;
        int acc_len;
        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            if (x_arr[x + u] >= 12289)
            {
                return 0;
            }
        }
        out_len = ((n * 14) + 7) >> 3;
        if (out_arr == null)
        {
            return out_len;
        }
        if (out_len > outlenmax)
        {
            return 0;
        }
        buf = out;
        acc = 0;
        acc_len = 0;
        for (u = 0; u < n; u++)
        {
            acc = (acc << 14) | x_arr[x + u];
            acc_len += 14;
            while (acc_len >= 8)
            {
                acc_len -= 8;
                out_arr[buf++] = (byte)(acc >>> acc_len);
            }
        }
        if (acc_len > 0)
        {
            out_arr[buf] = (byte)(acc << (8 - acc_len));
        }
        return out_len;
    }

    static int modq_decode(int x, short[] x_arr, int logn, int in, byte[] in_arr, int inlenmax)
    {
        int n, in_len, u;
        int buf;
        int acc;
        int acc_len;

        n = 1 << logn;
        in_len = ((n * 14) + 7) >> 3;
        if (in_len > inlenmax)
        {
            return 0;
        }
        buf = in;
        acc = 0;
        acc_len = 0;
        u = 0;
        while (u < n)
        {
            acc = (acc << 8) | in_arr[in + buf];
            buf++;
            acc_len += 8;
            if (acc_len >= 14)
            {
                int w;

                acc_len -= 14;
                w = (acc >>> acc_len) & 0x3FFF;
                if (w >= 12289)
                {
                    return 0;
                }
                x_arr[x + u] = (short)w;
                u++;
            }
        }
        if ((acc & ((1 << acc_len) - 1)) != 0)
        {
            return 0;
        }
        return in_len;
    }

    /*
    // variable time hash to point
    void hash_to_point_vartime(FalconSHAKE256 sc, int x, short[] x_arr, int logn) {
        int n;

        n = 1 << logn;
        while (n > 0) {
            byte[] buf;
            int w;

            buf = sc.extract(2);
            w = (Byte.toUnsignedInt(buf[0]) << 8) | Byte.toUnsignedInt(buf[1]);
            if (w < 61445) {
                while (w >= 12289) {
                    w -= 12289;
                }
			    x_arr[x ++] = (short)w;
                n --;
            }
        }
    }*/

    private static final short[] overtab = {
        0, /* unused */
        65,
        67,
        71,
        77,
        86,
        100,
        122,
        154,
        205,
        287
    };

    // constant time hash to point
    static void hash_to_point_ct(FalconSHAKE256 sc, int x, short[] x_arr, int logn)
    {
        int n, n2, u, m, p, over;
        short[] tt1;
        short[] tt2 = new short[63];

        n = 1 << logn;
        n2 = n << 1;
        over = overtab[logn];
        m = n + over;
        tt1 = new short[m];
        for (u = 0; u < m; u++)
        {
            byte[] buf;
            int w, wr;

            buf = sc.extract(2);
            w = (Byte.toUnsignedInt(buf[0]) << 8) | Byte.toUnsignedInt(buf[1]);
            wr = w - (24578 & (((w - 24578) >>> 31) - 1));
            wr = wr - (24578 & (((wr - 24578) >>> 31) - 1));
            wr = wr - (12289 & (((wr - 12289) >>> 31) - 1));
            wr |= ((w - 61445) >>> 31) - 1;
            if (u < n)
            {
                x_arr[x + u] = (short)wr;
            }
            else if (u < n2)
            {
                tt1[u - n] = (short)wr;
            }
            else
            {
                tt2[u - n2] = (short)wr;
            }
        }
        for (p = 1; p <= over; p <<= 1)
        {
            int v;

            /*
             * In the loop below:
             *
             *   - v contains the index of the final destination of
             *     the value; it is recomputed dynamically based on
             *     whether values are valid or not.
             *
             *   - u is the index of the value we consider ("source");
             *     its address is s.
             *
             *   - The loop may swap the value with the one at index
             *     u-p. The address of the swap destination is d.
             */
            v = 0;
            for (u = 0; u < m; u++)
            {
                int s, d;
                short[] s_a, d_a;
                int j, sv, dv, mk;

                if (u < n)
                {
                    s = u;
                    s_a = x_arr;
                }
                else if (u < n2)
                {
                    s = u - n;
                    s_a = tt1;
                }
                else
                {
                    s = u - n2;
                    s_a = tt2;
                }
                sv = s;

                /*
                 * The value in sv should ultimately go to
                 * address v, i.e. jump back by u-v slots.
                 */
                j = u - v;

                /*
                 * We increment v for the next iteration, but
                 * only if the source value is valid. The mask
                 * 'mk' is -1 if the value is valid, 0 otherwise,
                 * so we _subtract_ mk.
                 */
                mk = (sv >>> 15) - 1;
                v -= mk;

                /*
                 * In this loop we consider jumps by p slots; if
                 * u < p then there is nothing more to do.
                 */
                if (u < p)
                {
                    continue;
                }

                /*
                 * Destination for the swap: value at address u-p.
                 */
                if ((u - p) < n)
                {
                    d = u - p;
                    d_a = x_arr;
                }
                else if ((u - p) < n2)
                {
                    d = (u - p) - n;
                    d_a = tt1;
                }
                else
                {
                    d = (u - p) - n2;
                    d_a = tt2;
                }
                dv = d;

                /*
                 * The swap should be performed only if the source
                 * is valid AND the jump j has its 'p' bit set.
                 */
                mk &= -(((j & p) + 0x1FF) >>> 9);

                s_a[s] = (short)(sv ^ (mk & (sv ^ dv)));
                d_a[d] = (short)(dv ^ (mk & (sv ^ dv)));
            }
        }
    }

    static int comp_encode(int out, byte[] out_arr, int max_out_len, int x, short[] x_arr, int logn)
    {
        byte[] buf;
        int n, u, v;
        int acc;
        int acc_len;

        n = 1 << logn;
        buf = out_arr;

        /*
         * Make sure that all values are within the -2047..+2047 range.
         */
        for (u = 0; u < n; u++)
        {
            if (x_arr[x + u] < -2047 || x_arr[x + u] > +2047)
            {
                return 0;
            }
        }

        acc = 0;
        acc_len = 0;
        v = 0;
        for (u = 0; u < n; u++)
        {
            int t;
            int w;

            /*
             * Get sign and absolute value of next integer; push the
             * sign bit.
             */
            acc <<= 1;
            t = x_arr[x + u];
            if (t < 0)
            {
                t = -t;
                acc |= 1;
            }
            w = t;

            /*
             * Push the low 7 bits of the absolute value.
             */
            acc <<= 7;
            acc |= w & 127;
            w >>= 7;

            /*
             * We pushed exactly 8 bits.
             */
            acc_len += 8;

            /*
             * Push as many zeros as necessary, then a one. Since the
             * absolute value is at most 2047, w can only range up to
             * 15 at this point, thus we will add at most 16 bits
             * here. With the 8 bits above and possibly up to 7 bits
             * from previous iterations, we may go up to 31 bits, which
             * will fit in the accumulator, which is an uint32_t.
             */
            acc <<= (w + 1);
            acc |= 1;
            acc_len += w + 1;

            /*
             * Produce all full bytes.
             */
            while (acc_len >= 8)
            {
                acc_len -= 8;
                if (buf != null)
                {
                    if (v >= max_out_len)
                    {
                        return 0;
                    }
                    buf[out + v] = (byte)(acc >>> acc_len);
                }
                v++;
            }
        }

        /*
         * Flush remaining bits (if any).
         */
        if (acc_len > 0)
        {
            if (buf != null)
            {
                if (v >= max_out_len)
                {
                    return 0;
                }
                buf[out + v] = (byte)(acc << (8 - acc_len));
            }
            v++;
        }

        return v;
    }

    static int comp_decode(int x, short[] x_arr, int logn, int in, byte[] in_arr, int max_in_len)
    {
        byte[] buf;
        int n, u, v;
        int acc;
        int acc_len;

        n = 1 << logn;
        buf = in_arr;
        acc = 0;
        acc_len = 0;
        v = 0;
        for (u = 0; u < n; u++)
        {
            int b, s, m;

            /*
             * Get next eight bits: sign and low seven bits of the
             * absolute value.
             */
            if (v >= max_in_len)
            {
                return 0;
            }
            acc = (acc << 8) | Byte.toUnsignedInt(buf[in + v]);
            v++;
            b = acc >> acc_len;
            s = b & 128;
            m = b & 127;

            /*
             * Get next bits until a 1 is reached.
             */
            for (; ; )
            {
                if (acc_len == 0)
                {
                    if (v >= max_in_len)
                    {
                        return 0;
                    }
                    acc = (acc << 8) | buf[in + v];
                    v++;
                    acc_len = 8;
                }
                acc_len--;
                if (((acc >>> acc_len) & 1) != 0)
                {
                    break;
                }
                m += 128;
                if (m > 2047)
                {
                    return 0;
                }
            }

            /*
             * "-0" is forbidden.
             */
            if (s != 0 && m == 0)
            {
                return 0;
            }

            x_arr[x + u] = (short)(s != 0 ? -m : m);
        }

        /*
         * Unused bits in the last byte must be zero.
         */
        if ((acc & ((1 << acc_len) - 1)) != 0)
        {
            return 0;
        }

        return v;
    }

    static final int l2bound[] = {
        0,    /* unused */
        101498,
        208714,
        428865,
        892039,
        1852696,
        3842630,
        7959734,
        16468416,
        34034726,
        70265242
    };

    static boolean is_short(short[] s1, short[] s2, int logn)
    {
        int n, u;
        int s, ng;

        n = 1 << logn;
        s = 0;
        ng = 0;
        for (u = 0; u < n; u++)
        {
            int z;

            z = s1[u];
            s += (z * z);
            ng |= s;
            z = s2[u];
            s += (z * z);
            ng |= s;
        }
        s |= -(ng >>> 31);

        return s <= l2bound[logn];
    }
}
