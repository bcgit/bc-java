package org.bouncycastle.pqc.crypto.saber;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

import java.security.SecureRandom;

public class SABEREngine
{
    private static final int SABER_EQ = 13;
    private static final int SABER_EP = 10;
    private static final int SABER_N = 256;

    private static final int SABER_SEEDBYTES = 32;
    private static final int SABER_NOISE_SEEDBYTES = 32;
    private static final int SABER_KEYBYTES = 32;
    private static final int SABER_HASHBYTES = 32;

    // all of these should not be static
    private static final int SABER_L = 3;

    /**
     * #if SABER_L == 2
     * 	#define SABER_MU 10
     * 	#define SABER_ET 3
     * #elif SABER_L == 3
     * 	#define SABER_MU 8
     * 	#define SABER_ET 4
     * #elif SABER_L == 4
     * 	#define SABER_MU 6
     * 	#define SABER_ET 6
     */

    private static final int SABER_MU = 8;
    private static final int SABER_ET = 4;

    private static final int SABER_POLYCOINBYTES = (SABER_MU * SABER_N / 8);
    private static final int SABER_POLYBYTES = (SABER_EQ * SABER_N / 8);
    private static final int SABER_POLYVECBYTES = (SABER_L * SABER_POLYBYTES);
    private static final int SABER_POLYCOMPRESSEDBYTES = (SABER_EP * SABER_N / 8);
    private static final int SABER_POLYVECCOMPRESSEDBYTES = (SABER_L * SABER_POLYCOMPRESSEDBYTES);
    private static final int SABER_SCALEBYTES_KEM = (SABER_ET * SABER_N / 8);
    private static final int SABER_INDCPA_PUBLICKEYBYTES = (SABER_POLYVECCOMPRESSEDBYTES + SABER_SEEDBYTES);
    private static final int SABER_INDCPA_SECRETKEYBYTES = (SABER_POLYVECBYTES);
    private static final int SABER_PUBLICKEYBYTES = (SABER_INDCPA_PUBLICKEYBYTES);
    private static final int SABER_SECRETKEYBYTES = (SABER_INDCPA_SECRETKEYBYTES + SABER_INDCPA_PUBLICKEYBYTES + SABER_HASHBYTES + SABER_KEYBYTES);
    private static final int SABER_BYTES_CCA_DEC = (SABER_POLYVECCOMPRESSEDBYTES + SABER_SCALEBYTES_KEM);

    //
    private static int h1 = (1 << (SABER_EQ - SABER_EP - 1));
    private static int h2 = ((1 << (SABER_EP - 2)) - (1 << (SABER_EP - SABER_ET - 1)) + (1 << (SABER_EQ - SABER_EP - 1)));


    public static void main(String[] args)
    {

        byte[] pk = new byte[SABER_INDCPA_PUBLICKEYBYTES];
        byte[] sk = new byte[SABER_INDCPA_SECRETKEYBYTES];

        // key pair gen
        short[][][] A = new short[SABER_L][SABER_L][SABER_N];
        short[][] s = new short[SABER_L][SABER_N];
        short[][] b = new short[SABER_L][SABER_N];
        b[0][0] = 0;//todo remove?

        byte[] seed_A = new byte[SABER_SEEDBYTES];
        byte[] seed_s = new byte[SABER_NOISE_SEEDBYTES];
        int i, j;

        FixedSecureRandom random = new FixedSecureRandom(Hex.decode("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d"));
        random.nextBytes(seed_A);

        Xof digest = new SHAKEDigest(128);
        digest.update(seed_A, 0, SABER_SEEDBYTES);
        digest.doFinal(seed_A, 0, SABER_SEEDBYTES);

        random = new FixedSecureRandom(Hex.decode("8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f"));
        random.nextBytes(seed_s);

        GenMatrix(A, seed_A);
        System.out.print("A: ");
        for (i = 0; i < SABER_L; i++)
            for (j = 0; j < SABER_L; j++)
                for (int k = 0; k < SABER_N; k++)
                    System.out.printf("%04x ", A[i][j][k]);
        System.out.println();

        GenSecret(s, seed_s);
        System.out.print("s: ");
        for (i = 0; i < SABER_L; i++)
            for (j = 0; j < SABER_N; j++)
                System.out.printf("%04x ", s[i][j]);
        System.out.println();

        MatrixVectorMul(A, s, b, 1);

        System.out.print("b: ");
        for (i = 0; i < SABER_L; i++)
            for (j = 0; j < SABER_N; j++)
                System.out.printf("%04x ", b[i][j]);
        System.out.println();

        for (i = 0; i < SABER_L; i++)
        {
            for (j = 0; j < SABER_N; j++)
            {
                b[i][j] = (short) (((b[i][j] + h1)&0xffff) >>> (SABER_EQ - SABER_EP));
            }
        }
        System.out.print("b: ");
        for (i = 0; i < SABER_L; i++)
            for (j = 0; j < SABER_N; j++)
                System.out.printf("%04x ", b[i][j]);
        System.out.println();

        POLVECq2BS(sk, s);
        POLVECp2BS(pk, b);
        System.arraycopy(seed_A, 0, pk, SABER_POLYVECCOMPRESSEDBYTES, seed_A.length);


        System.out.println("pk: " + ByteUtils.toHexString(pk));
        System.out.println("sk: " + ByteUtils.toHexString(sk));
    }

    private static void GenMatrix(short[][][] A, byte[] seed)
    {
        byte[] buf = new byte[SABER_L * SABER_POLYVECBYTES];
        int i;

        Xof digest = new SHAKEDigest(128);
        digest.update(seed, 0, SABER_SEEDBYTES);
        digest.doFinal(buf, 0, buf.length);

        for (i = 0; i < SABER_L; i++)
        {
            BS2POLVECq(buf, i * SABER_POLYVECBYTES, A[i]);
        }
    }

    private static void GenSecret(short[][] s, byte[] seed)
    {
        byte[] buf = new byte[SABER_L * SABER_POLYCOINBYTES];
        int i;
        Xof digest = new SHAKEDigest(128);
        digest.update(seed, 0, SABER_NOISE_SEEDBYTES);
        digest.doFinal(buf, 0, buf.length);
        System.out.println("buf: " + ByteUtils.toHexString(buf));

        for (i = 0; i < SABER_L; i++)
        {
            cbd(s[i], buf, i * SABER_POLYCOINBYTES);
        }

    }

    static void POLT2BS(byte bytes[], short data[])
    {
        short j, offset_byte, offset_data;
        if (SABER_ET == 3)
        {
            for (j = 0; j < SABER_N / 8; j++)
            {
                offset_byte = (short) (3 * j);
                offset_data = (short) (8 * j);
                bytes[offset_byte + 0] = (byte) ((data[offset_data + 0] & 0x7) | ((data[offset_data + 1] & 0x7) << 3) | ((data[offset_data + 2] & 0x3) << 6));
                bytes[offset_byte + 1] = (byte) (((data[offset_data + 2] >> 2) & 0x01) | ((data[offset_data + 3] & 0x7) << 1) | ((data[offset_data + 4] & 0x7) << 4) | (((data[offset_data + 5]) & 0x01) << 7));
                bytes[offset_byte + 2] = (byte) (((data[offset_data + 5] >> 1) & 0x03) | ((data[offset_data + 6] & 0x7) << 2) | ((data[offset_data + 7] & 0x7) << 5));
            }
        }
        else if (SABER_ET == 4)
        {
            for (j = 0; j < SABER_N / 2; j++)
            {
                offset_byte = j;
                offset_data = (short) (2 * j);
                bytes[offset_byte] = (byte) ((data[offset_data] & 0x0f) | ((data[offset_data + 1] & 0x0f) << 4));
            }
        }
        else if(SABER_ET == 6)
        {
            for (j = 0; j < SABER_N / 4; j++)
            {
                offset_byte = (short) (3 * j);
                offset_data = (short) (4 * j);
                bytes[offset_byte + 0] = (byte) ((data[offset_data + 0] & 0x3f) | ((data[offset_data + 1] & 0x03) << 6));
                bytes[offset_byte + 1] = (byte) (((data[offset_data + 1] >> 2) & 0x0f) | ((data[offset_data + 2] & 0x0f) << 4));
                bytes[offset_byte + 2] = (byte) (((data[offset_data + 2] >> 4) & 0x03) | ((data[offset_data + 3] & 0x3f) << 2));
            }
        }
    }

    static void BS2POLT(byte bytes[], short data[])
    {
        short j, offset_byte, offset_data;
        if (SABER_ET == 3)
        {
            for (j = 0; j < SABER_N / 8; j++)
            {
                offset_byte = (short) (3 * j);
                offset_data = (short) (8 * j);
                data[offset_data + 0] = (short) ((bytes[offset_byte + 0]) & 0x07);
                data[offset_data + 1] = (short) (((bytes[offset_byte + 0]) >> 3) & 0x07);
                data[offset_data + 2] = (short) ((((bytes[offset_byte + 0]) >> 6) & 0x03) | (((bytes[offset_byte + 1]) & 0x01) << 2));
                data[offset_data + 3] = (short) (((bytes[offset_byte + 1]) >> 1) & 0x07);
                data[offset_data + 4] = (short) (((bytes[offset_byte + 1]) >> 4) & 0x07);
                data[offset_data + 5] = (short) ((((bytes[offset_byte + 1]) >> 7) & 0x01) | (((bytes[offset_byte + 2]) & 0x03) << 1));
                data[offset_data + 6] = (short) ((bytes[offset_byte + 2] >> 2) & 0x07);
                data[offset_data + 7] = (short) ((bytes[offset_byte + 2] >> 5) & 0x07);
            }
        }
        else if (SABER_ET == 4)
        {
            for (j = 0; j < SABER_N / 2; j++)
            {
                offset_byte = j;
                offset_data = (byte) (2 * j);
                data[offset_data] = (short) (bytes[offset_byte] & 0x0f);
                data[offset_data + 1] = (short) ((bytes[offset_byte] >> 4) & 0x0f);
            }
        }
        else if (SABER_ET == 6)
        {
            for (j = 0; j < SABER_N / 4; j++)
            {
                offset_byte = (short) (3 * j);
                offset_data = (short) (4 * j);
                data[offset_data + 0] = (short) (bytes[offset_byte + 0] & 0x3f);
                data[offset_data + 1] = (short) (((bytes[offset_byte + 0] >> 6) & 0x03) | ((bytes[offset_byte + 1] & 0x0f) << 2));
                data[offset_data + 2] = (short) (((bytes[offset_byte + 1] & 0xff) >> 4) | ((bytes[offset_byte + 2] & 0x03) << 4));
                data[offset_data + 3] = (short) ((bytes[offset_byte + 2] & 0xff) >> 2);
            }
        }

    }

    static void POLq2BS(byte bytes[], int byteIndex, short data[])
    {
        short j, offset_byte, offset_data;
        for (j = 0; j < SABER_N / 8; j++)
        {
            offset_byte = (short) (13 * j);
            offset_data = (short) (8 * j);
            bytes[byteIndex + offset_byte + 0] = (byte) (data[offset_data + 0] & (0xff));
            bytes[byteIndex + offset_byte + 1] = (byte) (((data[offset_data + 0] >> 8) & 0x1f) | ((data[offset_data + 1] & 0x07) << 5));
            bytes[byteIndex + offset_byte + 2] = (byte) ((data[offset_data + 1] >> 3) & 0xff);
            bytes[byteIndex + offset_byte + 3] = (byte) (((data[offset_data + 1] >> 11) & 0x03) | ((data[offset_data + 2] & 0x3f) << 2));
            bytes[byteIndex + offset_byte + 4] = (byte) (((data[offset_data + 2] >> 6) & 0x7f) | ((data[offset_data + 3] & 0x01) << 7));
            bytes[byteIndex + offset_byte + 5] = (byte) ((data[offset_data + 3] >> 1) & 0xff);
            bytes[byteIndex + offset_byte + 6] = (byte) (((data[offset_data + 3] >> 9) & 0x0f) | ((data[offset_data + 4] & 0x0f) << 4));
            bytes[byteIndex + offset_byte + 7] = (byte) ((data[offset_data + 4] >> 4) & 0xff);
            bytes[byteIndex + offset_byte + 8] = (byte) (((data[offset_data + 4] >> 12) & 0x01) | ((data[offset_data + 5] & 0x7f) << 1));
            bytes[byteIndex + offset_byte + 9] = (byte) (((data[offset_data + 5] >> 7) & 0x3f) | ((data[offset_data + 6] & 0x03) << 6));
            bytes[byteIndex + offset_byte + 10] = (byte) ((data[offset_data + 6] >> 2) & 0xff);
            bytes[byteIndex + offset_byte + 11] = (byte) (((data[offset_data + 6] >> 10) & 0x07) | ((data[offset_data + 7] & 0x1f) << 3));
            bytes[byteIndex + offset_byte + 12] = (byte) ((data[offset_data + 7] >> 5) & 0xff);
        }
    }

    static void BS2POLq(byte bytes[], int byteIndex, short data[])
    {
        short j, offset_byte, offset_data;
        for (j = 0; j < SABER_N / 8; j++)
        {
            offset_byte = (short) (13 * j);
            offset_data = (short) (8 * j);
            data[offset_data + 0] = (short) ((bytes[byteIndex + offset_byte + 0] & (0xff)) | ((bytes[byteIndex + offset_byte + 1] & 0x1f) << 8));
            data[offset_data + 1] = (short) ((bytes[byteIndex + offset_byte + 1] >> 5 & (0x07)) | ((bytes[byteIndex + offset_byte + 2] & 0xff) << 3) | ((bytes[byteIndex + offset_byte + 3] & 0x03) << 11));
            data[offset_data + 2] = (short) ((bytes[byteIndex + offset_byte + 3] >> 2 & (0x3f)) | ((bytes[byteIndex + offset_byte + 4] & 0x7f) << 6));
            data[offset_data + 3] = (short) ((bytes[byteIndex + offset_byte + 4] >> 7 & (0x01)) | ((bytes[byteIndex + offset_byte + 5] & 0xff) << 1) | ((bytes[byteIndex + offset_byte + 6] & 0x0f) << 9));
            data[offset_data + 4] = (short) ((bytes[byteIndex + offset_byte + 6] >> 4 & (0x0f)) | ((bytes[byteIndex + offset_byte + 7] & 0xff) << 4) | ((bytes[byteIndex + offset_byte + 8] & 0x01) << 12));
            data[offset_data + 5] = (short) ((bytes[byteIndex + offset_byte + 8] >> 1 & (0x7f)) | ((bytes[byteIndex + offset_byte + 9] & 0x3f) << 7));
            data[offset_data + 6] = (short) ((bytes[byteIndex + offset_byte + 9] >> 6 & (0x03)) | ((bytes[byteIndex + offset_byte + 10] & 0xff) << 2) | ((bytes[byteIndex + offset_byte + 11] & 0x07) << 10));
            data[offset_data + 7] = (short) ((bytes[byteIndex + offset_byte + 11] >> 3 & (0x1f)) | ((bytes[byteIndex + offset_byte + 12] & 0xff) << 5));
        }
    }

    static void POLp2BS(byte bytes[], int byteIndex, short data[])
    {
        short j, offset_byte, offset_data;
        for (j = 0; j < SABER_N / 4; j++)
        {
            offset_byte = (short) (5 * j);
            offset_data = (short) (4 * j);
            bytes[byteIndex + offset_byte + 0] = (byte) (data[offset_data + 0] & (0xff));
            bytes[byteIndex + offset_byte + 1] = (byte) (((data[offset_data + 0] >> 8) & 0x03) | ((data[offset_data + 1] & 0x3f) << 2));
            bytes[byteIndex + offset_byte + 2] = (byte) (((data[offset_data + 1] >> 6) & 0x0f) | ((data[offset_data + 2] & 0x0f) << 4));
            bytes[byteIndex + offset_byte + 3] = (byte) (((data[offset_data + 2] >> 4) & 0x3f) | ((data[offset_data + 3] & 0x03) << 6));
            bytes[byteIndex + offset_byte + 4] = (byte) ((data[offset_data + 3] >> 2) & 0xff);
        }
    }

    static void BS2POLp(byte bytes[], int byteIndex, short data[])
    {
        byte j, offset_byte, offset_data;
        for (j = 0; j < SABER_N / 4; j++)
        {
            offset_byte = (byte) (5 * j);
            offset_data = (byte) (4 * j);
            data[offset_data + 0] = (short) ((bytes[byteIndex + offset_byte + 0] & (0xff)) | ((bytes[byteIndex + offset_byte + 1] & 0x03) << 8));
            data[offset_data + 1] = (short) (((bytes[byteIndex + offset_byte + 1] >> 2) & (0x3f)) | ((bytes[byteIndex + offset_byte + 2] & 0x0f) << 6));
            data[offset_data + 2] = (short) (((bytes[byteIndex + offset_byte + 2] >> 4) & (0x0f)) | ((bytes[byteIndex + offset_byte + 3] & 0x3f) << 4));
            data[offset_data + 3] = (short) (((bytes[byteIndex + offset_byte + 3] >> 6) & (0x03)) | ((bytes[byteIndex + offset_byte + 4] & 0xff) << 2));
        }
    }

    static void POLVECq2BS(byte bytes[], short data[][])
    {
        byte i;
        for (i = 0; i < SABER_L; i++)
        {
            POLq2BS(bytes, i * SABER_POLYBYTES, data[i]);
        }
    }

    static void BS2POLVECq(byte bytes[], int byteIndex, short data[][])
    {
        byte i;
        for (i = 0; i < SABER_L; i++)
        {
            BS2POLq(bytes, byteIndex + i * SABER_POLYBYTES, data[i]);
        }
    }

    static void POLVECp2BS(byte bytes[], short data[][])
    {
        byte i;
        for (i = 0; i < SABER_L; i++)
        {
            POLp2BS(bytes, i * (SABER_EP * SABER_N / 8), data[i]);
        }
    }

    static void BS2POLVECp(byte bytes[], short data[][])
    {
        byte i;
        for (i = 0; i < SABER_L; i++)
        {
            BS2POLp(bytes, i * (SABER_EP * SABER_N / 8), data[i]);
        }
    }

    static void BS2POLmsg(byte bytes[], short data[])
    {
        byte i, j;
        for (j = 0; j < SABER_KEYBYTES; j++)
        {
            for (i = 0; i < 8; i++)
            {
                data[j * 8 + i] = (short) ((bytes[j] >> i) & 0x01);
            }
        }
    }

    static void POLmsg2BS(byte bytes[], short data[])
    {
        byte i, j;
        //memset(bytes, 0, SABER_KEYBYTES);

        for (j = 0; j < SABER_KEYBYTES; j++)
        {
            for (i = 0; i < 8; i++)
            {
                bytes[j] = (byte) (bytes[j] | ((data[j * 8 + i] & 0x01) << i));
            }
        }
    }

    static long load_littleendian(byte[] x, int offset, int bytes)
    {
        int i;
        long r = (x[offset + 0]&0xff);
        for (i = 1; i < bytes; i++)
        {
            r |= (x[offset + i]&0xff) << (8 * i);
        }
        return r;
    }
    
    private static void cbd(short[] s, byte[] buf, int offset)
    {
        int[] a = new int[4], b = new int[4];
        int i, j;
        if(SABER_MU == 6)
        {
            int t, d;
            for (i = 0; i < SABER_N / 4; i++)
            {
                t = (int) load_littleendian(buf, offset + 3 * i, 3);
                d = 0;
                for (j = 0; j < 3; j++)
                    d += (t >> j) & 0x249249;

                a[0] = d & 0x7;
                b[0] = (d >>> 3) & 0x7;
                a[1] = (d >>> 6) & 0x7;
                b[1] = (d >>> 9) & 0x7;
                a[2] = (d >>> 12) & 0x7;
                b[2] = (d >>> 15) & 0x7;
                a[3] = (d >>> 18) & 0x7;
                b[3] = (d >>> 21);

                s[4 * i + 0] = (short) (a[0] - b[0]);
                s[4 * i + 1] = (short) (a[1] - b[1]);
                s[4 * i + 2] = (short) (a[2] - b[2]);
                s[4 * i + 3] = (short) (a[3] - b[3]);
            }
        }
        else if(SABER_MU == 8)
        {
            int t, d;
            for (i = 0; i < SABER_N / 4; i++)
            {

                t = (int) load_littleendian(buf,offset + 4 * i, 4);
                d = 0;
                for (j = 0; j < 4; j++)
                    d += (t >>> j) & 0x11111111;


                a[0] = d & 0xf;
                b[0] = (d >>> 4) & 0xf;
                a[1] = (d >>> 8) & 0xf;
                b[1] = (d >>> 12) & 0xf;
                a[2] = (d >>> 16) & 0xf;
                b[2] = (d >>> 20) & 0xf;
                a[3] = (d >>> 24) & 0xf;
                b[3] = (d >>> 28);

                s[4 * i + 0] = (short) (a[0] - b[0]);
                s[4 * i + 1] = (short) (a[1] - b[1]);
                s[4 * i + 2] = (short) (a[2] - b[2]);
                s[4 * i + 3] = (short) (a[3] - b[3]);
            }
        }
        else if(SABER_MU == 10)
        {
            long t, d;
            for (i = 0; i < SABER_N / 4; i++)
            {
                t = load_littleendian(buf,offset + 5 * i, 5);
                d = 0;
                for (j = 0; j < 5; j++)
                    d += (t >> j) & 0x0842108421L;

                a[0] = (int) (d & 0x1f);
                b[0] = (int) ((d >> 5) & 0x1f);
                a[1] = (int) ((d >> 10) & 0x1f);
                b[1] = (int) ((d >> 15) & 0x1f);
                a[2] = (int) ((d >> 20) & 0x1f);
                b[2] = (int) ((d >> 25) & 0x1f);
                a[3] = (int) ((d >> 30) & 0x1f);
                b[3] = (int) (d >> 35);

                s[4 * i + 0] = (short) (a[0] - b[0]);
                s[4 * i + 1] = (short) (a[1] - b[1]);
                s[4 * i + 2] = (short) (a[2] - b[2]);
                s[4 * i + 3] = (short) (a[3] - b[3]);
            }
        }
    }

    private static final int KARATSUBA_N = 64;

    static short OVERFLOWING_MUL(int x, int y)
    {
        return (short)(x*y);
    }
    
    static void karatsuba_simple(int[] a_1, int[] b_1, int[] result_final) {
        int[] d01 = new int[KARATSUBA_N / 2 - 1];
        int[] d0123 = new int[KARATSUBA_N / 2 - 1];
        int[] d23 = new int[KARATSUBA_N / 2 - 1];
        int[] result_d01 = new int[KARATSUBA_N - 1];

        int i, j;
        int acc1, acc2, acc3, acc4, acc5, acc6, acc7, acc8, acc9, acc10;

        for (i = 0; i < KARATSUBA_N / 4; i++) {
            acc1 = a_1[i]; //a0
            acc2 = a_1[i + KARATSUBA_N / 4]; //a1
            acc3 = a_1[i + 2 * KARATSUBA_N / 4]; //a2
            acc4 = a_1[i + 3 * KARATSUBA_N / 4]; //a3
            for (j = 0; j < KARATSUBA_N / 4; j++) {

                acc5 = b_1[j]; //b0
                acc6 = b_1[j + KARATSUBA_N / 4]; //b1

                result_final[i + j + 0 * KARATSUBA_N / 4] = (result_final[i + j + 0 * KARATSUBA_N / 4] + OVERFLOWING_MUL(acc1, acc5));
                result_final[i + j + 2 * KARATSUBA_N / 4] = (result_final[i + j + 2 * KARATSUBA_N / 4] + OVERFLOWING_MUL(acc2, acc6));

                acc7 = (acc5 + acc6); //b01
                acc8 = (acc1 + acc2); //a01
                d01[i + j] = (int) (d01[i + j] + (acc7 * (long)acc8));
                //--------------------------------------------------------

                acc7 = b_1[j + 2 * KARATSUBA_N / 4]; //b2
                acc8 = b_1[j + 3 * KARATSUBA_N / 4]; //b3
                result_final[i + j + 4 * KARATSUBA_N / 4] =
                        (result_final[i + j + 4 * KARATSUBA_N / 4] +
                                                        OVERFLOWING_MUL(acc7, acc3));

                result_final[i + j + 6 * KARATSUBA_N / 4] =
                        (result_final[i + j + 6 * KARATSUBA_N / 4] +
                                                        OVERFLOWING_MUL(acc8, acc4));

                acc9 = (acc3 + acc4);
                acc10 = (acc7 + acc8);
                d23[i + j] = (d23[i + j] + OVERFLOWING_MUL(acc9, acc10));
                //--------------------------------------------------------

                acc5 = (acc5 + acc7); //b02
                acc7 = (acc1 + acc3); //a02
                result_d01[i + j + 0 * KARATSUBA_N / 4] =
                        (result_d01[i + j + 0 * KARATSUBA_N / 4] +
                                                        OVERFLOWING_MUL(acc5, acc7));

                acc6 = (acc6 + acc8); //b13
                acc8 = (acc2 + acc4);
                result_d01[i + j + 2 * KARATSUBA_N / 4] =
                        (result_d01[i + j + 2 * KARATSUBA_N / 4] +
                                                        OVERFLOWING_MUL(acc6, acc8));

                acc5 = (acc5 + acc6);
                acc7 = (acc7 + acc8);
                d0123[i + j] = (d0123[i + j] + OVERFLOWING_MUL(acc5, acc7));
            }
        }

        // 2nd last stage

        for (i = 0; i < KARATSUBA_N / 2 - 1; i++) {
            d0123[i] = (d0123[i] - result_d01[i + 0 * KARATSUBA_N / 4] - result_d01[i + 2 * KARATSUBA_N / 4]);
            d01[i] = (d01[i] - result_final[i + 0 * KARATSUBA_N / 4] - result_final[i + 2 * KARATSUBA_N / 4]);
            d23[i] = (d23[i] - result_final[i + 4 * KARATSUBA_N / 4] - result_final[i + 6 * KARATSUBA_N / 4]);
        }

        for (i = 0; i < KARATSUBA_N / 2 - 1; i++) {
            result_d01[i + 1 * KARATSUBA_N / 4] = (result_d01[i + 1 * KARATSUBA_N / 4] + d0123[i]);
            result_final[i + 1 * KARATSUBA_N / 4] = (result_final[i + 1 * KARATSUBA_N / 4] + d01[i]);
            result_final[i + 5 * KARATSUBA_N / 4] = (result_final[i + 5 * KARATSUBA_N / 4] + d23[i]);
        }

        // Last stage
        for (i = 0; i < KARATSUBA_N - 1; i++) {
            result_d01[i] = (result_d01[i] - result_final[i] - result_final[i + KARATSUBA_N]);
        }

        for (i = 0; i < KARATSUBA_N - 1; i++) {
            result_final[i + 1 * KARATSUBA_N / 2] = (result_final[i + 1 * KARATSUBA_N / 2] + result_d01[i]);
        }

    }

    private static int SCHB_N = 16;

    private static int N_RES = (SABER_N << 1);
    private static int N_SB = (SABER_N >> 2);
    private static int N_SB_RES = (2*N_SB-1);
    
    static void toom_cook_4way (short[] a1, short[] b1, short[] result)
    {
        int inv3 = 43691, inv9 = 36409, inv15 = 61167;

        int[] aw1 = new int[N_SB],
                aw2 = new int[N_SB],
                aw3 = new int[N_SB],
                aw4 = new int[N_SB],
                aw5 = new int[N_SB],
                aw6 = new int[N_SB],
                aw7 = new int[N_SB];

        int[] bw1 = new int[N_SB],
                bw2 = new int[N_SB],
                bw3 = new int[N_SB],
                bw4 = new int[N_SB],
                bw5 = new int[N_SB],
                bw6 = new int[N_SB],
                bw7 = new int[N_SB];

        int[] w1 = new int[N_SB_RES],
                w2 = new int[N_SB_RES],
                w3 = new int[N_SB_RES],
                w4 = new int[N_SB_RES],
                w5 = new int[N_SB_RES],
                w6 = new int[N_SB_RES],
                w7 = new int[N_SB_RES];

        int r0, r1, r2, r3, r4, r5, r6, r7;
        short[] C;
        C = result;

        int i, j;

        // EVALUATION
        for (j = 0; j < N_SB; ++j) {
            r0 = a1[j];
            r1 = a1[j + N_SB];
            r2 = a1[j + N_SB * 2];
            r3 = a1[j + N_SB * 3];
            r4 = (short) (r0 + r2);
            r5 = (short) (r1 + r3);
            r6 = (short) (r4 + r5);
            r7 = (short) (r4 - r5);
            aw3[j] = r6;
            aw4[j] = r7;
            r4 = (short) (((r0 << 2) + r2) << 1);
            r5 = (short) ((r1 << 2) + r3);
            r6 = (short) (r4 + r5);
            r7 = (short) (r4 - r5);
            aw5[j] = r6;
            aw6[j] = r7;
            r4 = (short) ((r3 << 3) + (r2 << 2) + (r1 << 1) + r0);
            aw2[j] = r4;
            aw7[j] = r0;
            aw1[j] = r3;
        }
        for (j = 0; j < N_SB; ++j) {
            r0 = b1[j];
            r1 = b1[j + N_SB];
            r2 = b1[j + N_SB * 2];
            r3 = b1[j + N_SB * 3];
            r4 = r0 + r2;
            r5 = r1 + r3;
            r6 = r4 + r5;
            r7 = r4 - r5;
            bw3[j] = r6;
            bw4[j] = r7;
            r4 = ((r0 << 2) + r2) << 1;
            r5 = (r1 << 2) + r3;
            r6 = r4 + r5;
            r7 = r4 - r5;
            bw5[j] = r6;
            bw6[j] = r7;
            r4 = ((r3 << 3) + (r2 << 2) + (r1 << 1) + r0);
            bw2[j] = r4;
            bw7[j] = r0;
            bw1[j] = r3;
        }

        // MULTIPLICATION

        karatsuba_simple(aw1, bw1, w1);
        karatsuba_simple(aw2, bw2, w2);
        karatsuba_simple(aw3, bw3, w3);
        karatsuba_simple(aw4, bw4, w4);
        karatsuba_simple(aw5, bw5, w5);
        karatsuba_simple(aw6, bw6, w6);
        karatsuba_simple(aw7, bw7, w7);

        // INTERPOLATION
        for (i = 0; i < N_SB_RES; ++i) {
            r0 = w1[i];
            r1 = w2[i];
            r2 = w3[i];
            r3 = w4[i];
            r4 = w5[i];
            r5 = w6[i];
            r6 = w7[i];


            r1 = r1 + r4;
            r5 = (r5 - r4);
            r3 = ((r3&0xffff) - (r2&0xffff)) >>> 1;
            r4 = (r4 - r0);
            r4 = (r4 - (r6 << 6));
            r4 = ((r4 << 1) + r5);
            r2 = (r2 + r3);
            r1 = (r1 - (r2 << 6) - r2);
            r2 = (r2 - r6);
            r2 = (r2 - r0);
            r1 = (r1 + 45 * r2);
            r4 = (((((r4&0xffff) -(r2 << 3)) * inv3)) >> 3);
            r5 = (r5 + r1);
            r1 = ((r1&0xffff) + ( (r3&0xffff) << 4)) * inv9 >> 1;
            r3 = -(r3 + r1);
            r5 = ((30 * (r1&0xffff) - (r5&0xffff)) * inv15) >> 2;
            r2 = (r2 - r4);
            r1 = (r1 - r5);

            C[i]       += (r6&0xffff);
            C[i + 64]  += (r5&0xffff);
            C[i + 128] += (r4&0xffff);
            C[i + 192] += (r3&0xffff);
            C[i + 256] += (r2&0xffff);
            C[i + 320] += (r1&0xffff);
            C[i + 384] += (r0&0xffff);
        }
    }

    static void poly_mul_acc(short[] a, short[] b, short[] res)
    {
        int i;

        short[] c = new short[2 * SABER_N];

        toom_cook_4way(a, b, c);

        System.out.print("c: ");
        for (i = 0; i < 2 * SABER_N; i++)
            System.out.printf("%04x ", c[i]);
        System.out.println();

        /* reduction */
        for (i = SABER_N; i < 2 * SABER_N; i++)
        {
            res[i - SABER_N] += (c[i - SABER_N] - c[i]);
        }
    }

    static void MatrixVectorMul(short[][][] A, short[][] s, short[][] res, int transpose)
    {
        int i, j;
        for (i = 0; i < SABER_L; i++)
        {
            for (j = 0; j < SABER_L; j++)
            {
                if (transpose == 1)
                {
                    poly_mul_acc(A[j][i], s[j], res[i]);
                }
                else
                {
                    poly_mul_acc(A[i][j], s[j], res[i]);
                }
            }
        }
    }





}
