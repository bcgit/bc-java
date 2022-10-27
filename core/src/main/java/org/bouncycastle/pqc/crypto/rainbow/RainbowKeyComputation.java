package org.bouncycastle.pqc.crypto.rainbow;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.Arrays;

class RainbowKeyComputation
{
    private SecureRandom random;
    private Version version;
    private RainbowParameters rainbowParams;
    ComputeInField cf = new ComputeInField();

    private int v1;
    private int o1;
    private int o2;

    private byte[] sk_seed;
    private byte[] pk_seed;

    private short[][] s1;
    private short[][] t1;
    private short[][] t2;
    private short[][] t3;
    private short[][] t4;
    private short[][][] l1_F1;
    private short[][][] l1_F2;
    private short[][][] l2_F1;
    private short[][][] l2_F2;
    private short[][][] l2_F3;
    private short[][][] l2_F5;
    private short[][][] l2_F6;

    private short[][][] l1_Q1;
    private short[][][] l1_Q2;
    private short[][][] l1_Q3;
    private short[][][] l1_Q5;
    private short[][][] l1_Q6;
    private short[][][] l1_Q9;
    private short[][][] l2_Q1;
    private short[][][] l2_Q2;
    private short[][][] l2_Q3;
    private short[][][] l2_Q5;
    private short[][][] l2_Q6;
    private short[][][] l2_Q9;

    public RainbowKeyComputation(RainbowParameters params, SecureRandom random)
    {
        this.rainbowParams = params;
        this.random = random;
        this.version = this.rainbowParams.getVersion();

        this.v1 = rainbowParams.getV1();
        this.o1 = rainbowParams.getO1();
        this.o2 = rainbowParams.getO2();
    }

    public RainbowKeyComputation(RainbowParameters params, byte[] pk_seed, byte[] sk_seed)
    {
        this.rainbowParams = params;
        this.random = null;
        this.version = this.rainbowParams.getVersion();

        this.pk_seed = pk_seed;
        this.sk_seed = sk_seed;
        this.v1 = rainbowParams.getV1();
        this.o1 = rainbowParams.getO1();
        this.o2 = rainbowParams.getO2();
    }

    private void generate_S_and_T(SecureRandom sk_random)
    {
        this.s1 = RainbowUtil.generate_random_2d(sk_random, o1, o2);
        this.t1 = RainbowUtil.generate_random_2d(sk_random, v1, o1);
        this.t2 = RainbowUtil.generate_random_2d(sk_random, v1, o2);
        this.t3 = RainbowUtil.generate_random_2d(sk_random, o1, o2);
    }

    private void generate_B1_and_B2(SecureRandom pk_random)
    {
        this.l1_Q1 = RainbowUtil.generate_random(pk_random, o1, v1, v1, true);
        this.l1_Q2 = RainbowUtil.generate_random(pk_random, o1, v1, o1, false);
        this.l2_Q1 = RainbowUtil.generate_random(pk_random, o2, v1, v1, true);
        this.l2_Q2 = RainbowUtil.generate_random(pk_random, o2, v1, o1, false);
        this.l2_Q3 = RainbowUtil.generate_random(pk_random, o2, v1, o2, false);
        this.l2_Q5 = RainbowUtil.generate_random(pk_random, o2, o1, o1, true);
        this.l2_Q6 = RainbowUtil.generate_random(pk_random, o2, o1, o2, false);
    }

    // t4 = t1 * t3 -t2
    private void calculate_t4()
    {
        short[][] temp = cf.multiplyMatrix(this.t1, this.t3);
        this.t4 = cf.addMatrix(temp, this.t2);
    }

    private void calculate_F_from_Q()
    {
        // Layer 1
        // F1 = Q1
        this.l1_F1 = RainbowUtil.cloneArray(this.l1_Q1);

        // F2 = (Q1 + Q1_trans) * T1 + Q2
        this.l1_F2 = new short[this.o1][][];
        for (int k = 0; k < this.o1; k++)
        {
            this.l1_F2[k] = cf.addMatrixTranspose(this.l1_Q1[k]);
            this.l1_F2[k] = cf.multiplyMatrix(this.l1_F2[k], this.t1);
            this.l1_F2[k] = cf.addMatrix(this.l1_F2[k], this.l1_Q2[k]);
        }

        // Layer 2
        this.l2_F2 = new short[this.o2][][];
        this.l2_F3 = new short[this.o2][][];
        this.l2_F5 = new short[this.o2][][];
        this.l2_F6 = new short[this.o2][][];

        // F1 = Q1
        this.l2_F1 = RainbowUtil.cloneArray(this.l2_Q1);

        for (int k = 0; k < this.o2; k++)
        {
            // F2 = (Q1 + Q1_trans) * T1 + Q2
            short[][] Q1Q1_t = cf.addMatrixTranspose(this.l2_Q1[k]);
            this.l2_F2[k] = cf.multiplyMatrix(Q1Q1_t, this.t1);
            this.l2_F2[k] = cf.addMatrix(this.l2_F2[k], this.l2_Q2[k]);

            // F3 = (Q1 + Q1_trans) * T4 + Q2 * T3 + Q3
            this.l2_F3[k] = cf.multiplyMatrix(Q1Q1_t, this.t4);
            short[][] temp = cf.multiplyMatrix(this.l2_Q2[k], this.t3);
            this.l2_F3[k] = cf.addMatrix(this.l2_F3[k], temp);
            this.l2_F3[k] = cf.addMatrix(this.l2_F3[k], this.l2_Q3[k]);

            // F5 = UT( T1_trans * (Q1 * T1 + Q2) + Q5)
            temp = cf.multiplyMatrix(this.l2_Q1[k], this.t1);
            temp = cf.addMatrix(temp, this.l2_Q2[k]);
            short[][] T1_trans = cf.transpose(this.t1);
            this.l2_F5[k] = cf.multiplyMatrix(T1_trans, temp);
            this.l2_F5[k] = cf.addMatrix(this.l2_F5[k], this.l2_Q5[k]);
            this.l2_F5[k] = cf.to_UT(this.l2_F5[k]);

            // F6 = T1_trans * (Q1 + Q1_trans) * T4 + T1_trans * Q2 * T3 + T1_trans * Q3 + Q2_trans * T4 + (Q5 + Q5_trans) * T3 + Q6
            //    = T1_trans * F3 + Q2_trans * T4 + (Q5 + Q5_trans) * T3 + Q6
            this.l2_F6[k] = cf.multiplyMatrix(T1_trans, this.l2_F3[k]);
            temp = cf.multiplyMatrix(cf.transpose(this.l2_Q2[k]), this.t4);
            this.l2_F6[k] = cf.addMatrix(this.l2_F6[k], temp);
            temp = cf.addMatrixTranspose(this.l2_Q5[k]);
            temp = cf.multiplyMatrix(temp, this.t3);
            this.l2_F6[k] = cf.addMatrix(this.l2_F6[k], temp);
            this.l2_F6[k] = cf.addMatrix(this.l2_F6[k], this.l2_Q6[k]);
        }
    }

    private void calculate_Q_from_F()
    {
        short[][] T1_trans = cf.transpose(this.t1);
        short[][] T2_trans = cf.transpose(this.t2);

        // Layer 1
        // Q1 = F1
        this.l1_Q1 = RainbowUtil.cloneArray(this.l1_F1);

        // Q2 = (F1 + F1_trans) * T1 + F2
        this.l1_Q2 = new short[this.o1][][];
        for (int k = 0; k < this.o1; k++)
        {
            this.l1_Q2[k] = cf.addMatrixTranspose(this.l1_F1[k]);
            this.l1_Q2[k] = cf.multiplyMatrix(this.l1_Q2[k], this.t1);
            this.l1_Q2[k] = cf.addMatrix(this.l1_Q2[k], this.l1_F2[k]);
        }

        calculate_l1_Q3569(T1_trans, T2_trans);

        // Layer 2
        this.l2_Q2 = new short[this.o2][][];
        this.l2_Q3 = new short[this.o2][][];
        this.l2_Q5 = new short[this.o2][][];
        this.l2_Q6 = new short[this.o2][][];

        short[][] F1F1_t;
        short[][] temp;

        // Q1 = F1
        this.l2_Q1 = RainbowUtil.cloneArray(this.l2_F1);

        for (int k = 0; k < this.o2; k++)
        {
            // Q2 = (F1 + F1_trans) * T1 + F2
            F1F1_t = cf.addMatrixTranspose(this.l2_F1[k]);
            this.l2_Q2[k] = cf.multiplyMatrix(F1F1_t, this.t1);
            this.l2_Q2[k] = cf.addMatrix(this.l2_Q2[k], this.l2_F2[k]);

            // Q3 = (F1 + F1_trans) * T2 + F2 * T3 + F3
            this.l2_Q3[k] = cf.multiplyMatrix(F1F1_t, this.t2);
            temp = cf.multiplyMatrix(this.l2_F2[k], this.t3);
            this.l2_Q3[k] = cf.addMatrix(this.l2_Q3[k], temp);
            this.l2_Q3[k] = cf.addMatrix(this.l2_Q3[k], this.l2_F3[k]);

            // Q5 = UT( T1_trans * (F1 * T1 + F2) + F5)
            temp = cf.multiplyMatrix(this.l2_F1[k], this.t1);
            temp = cf.addMatrix(temp, this.l2_F2[k]);
            this.l2_Q5[k] = cf.multiplyMatrix(T1_trans, temp);
            this.l2_Q5[k] = cf.addMatrix(this.l2_Q5[k], this.l2_F5[k]);
            this.l2_Q5[k] = cf.to_UT(this.l2_Q5[k]);

            // Q6 = T1_trans * (F1 + F1_trans) * T2 + T1_trans * F2 * T3 + T1_trans * F3 + F2_trans * T2 + (F5 + F5_trans) * T3 + F6
            //    = T1_trans * Q3 + F2_trans * T2 + (F5 + F5_trans) * T3 + F6
            this.l2_Q6[k] = cf.multiplyMatrix(T1_trans, this.l2_Q3[k]);
            temp = cf.multiplyMatrix(cf.transpose(this.l2_F2[k]), this.t2);
            this.l2_Q6[k] = cf.addMatrix(this.l2_Q6[k], temp);
            temp = cf.addMatrixTranspose(this.l2_F5[k]);
            temp = cf.multiplyMatrix(temp, this.t3);
            this.l2_Q6[k] = cf.addMatrix(this.l2_Q6[k], temp);
            this.l2_Q6[k] = cf.addMatrix(this.l2_Q6[k], this.l2_F6[k]);
        }

        calculate_l2_Q9(T2_trans);
    }

    private void calculate_Q_from_F_cyclic()
    {
        short[][] T1_trans = cf.transpose(this.t1);
        short[][] T2_trans = cf.transpose(this.t2);

        calculate_l1_Q3569(T1_trans, T2_trans);

        calculate_l2_Q9(T2_trans);
    }

    private void calculate_l1_Q3569(short[][] T1_trans, short[][] T2_trans)
    {
        // Layer 1
        this.l1_Q3 = new short[this.o1][][];
        this.l1_Q5 = new short[this.o1][][];
        this.l1_Q6 = new short[this.o1][][];
        this.l1_Q9 = new short[this.o1][][];

        short[][] F2T3;
        short[][] temp;

        for (int k = 0; k < this.o1; k++)
        {
            // Q3 = (F1 + F1_trans) * T2 + F2 * T3
            F2T3 = cf.multiplyMatrix(this.l1_F2[k], this.t3);
            this.l1_Q3[k] = cf.addMatrixTranspose(this.l1_F1[k]);
            this.l1_Q3[k] = cf.multiplyMatrix(this.l1_Q3[k], this.t2);
            this.l1_Q3[k] = cf.addMatrix(this.l1_Q3[k], F2T3);

            // Q5 = UT( T1_trans * (F1 * T1 + F2))
            this.l1_Q5[k] = cf.multiplyMatrix(this.l1_F1[k], this.t1);
            this.l1_Q5[k] = cf.addMatrix(this.l1_Q5[k], this.l1_F2[k]);
            this.l1_Q5[k] = cf.multiplyMatrix(T1_trans, this.l1_Q5[k]);
            this.l1_Q5[k] = cf.to_UT(this.l1_Q5[k]);

            // Q6 = T1_trans * (F1 + F1_trans) * T2 + T1_trans * F2 * T3 + F2_trans * T2
            //    = T1_trans * Q3 + F2_trans * T2
            temp = cf.multiplyMatrix(cf.transpose(this.l1_F2[k]), this.t2);
            this.l1_Q6[k] = cf.multiplyMatrix(T1_trans, this.l1_Q3[k]);
            this.l1_Q6[k] = cf.addMatrix(this.l1_Q6[k], temp);

            // Q9 = UT( T2_trans * (F1 * T2 + F2 * T3))
            temp = cf.multiplyMatrix(this.l1_F1[k], this.t2);
            this.l1_Q9[k] = cf.addMatrix(temp, F2T3);
            this.l1_Q9[k] = cf.multiplyMatrix(T2_trans, this.l1_Q9[k]);
            this.l1_Q9[k] = cf.to_UT(this.l1_Q9[k]);
        }
    }

    private void calculate_l2_Q9(short[][] T2_trans)
    {
        // Layer 2
        this.l2_Q9 = new short[this.o2][][];

        short[][] temp;

        for (int k = 0; k < this.o2; k++)
        {
            // Q9 = UT( T2_trans * (F1 * T2 + F2 * T3 + F3) + T3_trans * ( F5 * T3 + F6))
            this.l2_Q9[k] = cf.multiplyMatrix(this.l2_F1[k], this.t2);
            temp = cf.multiplyMatrix(this.l2_F2[k], this.t3);
            this.l2_Q9[k] = cf.addMatrix(this.l2_Q9[k], temp);
            this.l2_Q9[k] = cf.addMatrix(this.l2_Q9[k], this.l2_F3[k]);
            this.l2_Q9[k] = cf.multiplyMatrix(T2_trans, this.l2_Q9[k]);
            temp = cf.multiplyMatrix(this.l2_F5[k], this.t3);
            temp = cf.addMatrix(temp, this.l2_F6[k]);
            temp = cf.multiplyMatrix(cf.transpose(this.t3), temp);
            this.l2_Q9[k] = cf.addMatrix(this.l2_Q9[k], temp);
            this.l2_Q9[k] = cf.to_UT(this.l2_Q9[k]);
        }
    }

    private void genKeyMaterial()
    {
        this.sk_seed = new byte[rainbowParams.getLen_skseed()];
        random.nextBytes(sk_seed);
        SecureRandom sk_random = new RainbowDRBG(sk_seed, rainbowParams.getHash_algo());

        generate_S_and_T(sk_random);

        // generating l1_F1, l1_F2, l2_F1, l2_F2, l2_F3, l2_F5, l2_F6
        this.l1_F1 = RainbowUtil.generate_random(sk_random, o1, v1, v1, true);
        this.l1_F2 = RainbowUtil.generate_random(sk_random, o1, v1, o1, false);
        this.l2_F1 = RainbowUtil.generate_random(sk_random, o2, v1, v1, true);
        this.l2_F2 = RainbowUtil.generate_random(sk_random, o2, v1, o1, false);
        this.l2_F3 = RainbowUtil.generate_random(sk_random, o2, v1, o2, false);
        this.l2_F5 = RainbowUtil.generate_random(sk_random, o2, o1, o1, true);
        this.l2_F6 = RainbowUtil.generate_random(sk_random, o2, o1, o2, false);

        // calculate the public key
        calculate_Q_from_F();
        // t4 = t1 * t3 - t2
        calculate_t4();

        this.l1_Q1 = cf.obfuscate_l1_polys(this.s1, this.l2_Q1, this.l1_Q1);
        this.l1_Q2 = cf.obfuscate_l1_polys(this.s1, this.l2_Q2, this.l1_Q2);
        this.l1_Q3 = cf.obfuscate_l1_polys(this.s1, this.l2_Q3, this.l1_Q3);
        this.l1_Q5 = cf.obfuscate_l1_polys(this.s1, this.l2_Q5, this.l1_Q5);
        this.l1_Q6 = cf.obfuscate_l1_polys(this.s1, this.l2_Q6, this.l1_Q6);
        this.l1_Q9 = cf.obfuscate_l1_polys(this.s1, this.l2_Q9, this.l1_Q9);
    }

    private void genPrivateKeyMaterial_cyclic()
    {
        SecureRandom sk_random = new RainbowDRBG(sk_seed, rainbowParams.getHash_algo());
        SecureRandom pk_random = new RainbowDRBG(pk_seed, rainbowParams.getHash_algo());

        generate_S_and_T(sk_random);
        // t4 = t1 * t3 - t2
        calculate_t4();

        // generating l1_Q1, l1_Q2, l2_Q1, l2_Q2, l2_Q3, l2_Q5, l2_Q6
        generate_B1_and_B2(pk_random);
        this.l1_Q1 = cf.obfuscate_l1_polys(this.s1, this.l2_Q1, this.l1_Q1);
        this.l1_Q2 = cf.obfuscate_l1_polys(this.s1, this.l2_Q2, this.l1_Q2);
        // calculate the rest parts of secret key from Qs and S,T
        calculate_F_from_Q();
    }

    private void genKeyMaterial_cyclic()
    {
        this.sk_seed = new byte[rainbowParams.getLen_skseed()];
        random.nextBytes(sk_seed);

        this.pk_seed = new byte[rainbowParams.getLen_pkseed()];
        random.nextBytes(pk_seed);

        genPrivateKeyMaterial_cyclic();

        // calculate the rest parts of public key: l1_Q3, l1_Q5, l1_Q6, l1_Q9, l2_Q9
        calculate_Q_from_F_cyclic();
        this.l1_Q3 = cf.obfuscate_l1_polys(this.s1, this.l2_Q3, this.l1_Q3);
        this.l1_Q5 = cf.obfuscate_l1_polys(this.s1, this.l2_Q5, this.l1_Q5);
        this.l1_Q6 = cf.obfuscate_l1_polys(this.s1, this.l2_Q6, this.l1_Q6);
        this.l1_Q9 = cf.obfuscate_l1_polys(this.s1, this.l2_Q9, this.l1_Q9);
    }

    public AsymmetricCipherKeyPair genKeyPairClassical()
    {
        genKeyMaterial();

        RainbowPublicKeyParameters pubKey = new RainbowPublicKeyParameters(this.rainbowParams,
            this.l1_Q1, this.l1_Q2, this.l1_Q3, this.l1_Q5, this.l1_Q6, this.l1_Q9,
            this.l2_Q1, this.l2_Q2, this.l2_Q3, this.l2_Q5, this.l2_Q6, this.l2_Q9);
        RainbowPrivateKeyParameters privKey = new RainbowPrivateKeyParameters(this.rainbowParams,
            this.sk_seed, this.s1, this.t1, this.t3, this.t4, this.l1_F1, this.l1_F2,
            this.l2_F1, this.l2_F2, this.l2_F3, this.l2_F5, this.l2_F6, pubKey.getEncoded());

        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    public AsymmetricCipherKeyPair genKeyPairCircumzenithal()
    {
        genKeyMaterial_cyclic();

        RainbowPublicKeyParameters pubKey = new RainbowPublicKeyParameters(this.rainbowParams,
            this.pk_seed, this.l1_Q3, this.l1_Q5, this.l1_Q6, this.l1_Q9, this.l2_Q9);
        RainbowPrivateKeyParameters privKey = new RainbowPrivateKeyParameters(this.rainbowParams,
            this.sk_seed, this.s1, this.t1, this.t3, this.t4, this.l1_F1, this.l1_F2,
            this.l2_F1, this.l2_F2, this.l2_F3, this.l2_F5, this.l2_F6, pubKey. getEncoded());

        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    public AsymmetricCipherKeyPair genKeyPairCompressed()
    {
        genKeyMaterial_cyclic();

        RainbowPublicKeyParameters pubKey = new RainbowPublicKeyParameters(this.rainbowParams,
            this.pk_seed, this.l1_Q3, this.l1_Q5, this.l1_Q6, this.l1_Q9, this.l2_Q9);
        RainbowPrivateKeyParameters privKey = new RainbowPrivateKeyParameters(this.rainbowParams,
            this.pk_seed, this.sk_seed, pubKey.getEncoded());

        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    RainbowPrivateKeyParameters generatePrivateKey()
    {
        this.sk_seed = Arrays.clone(sk_seed);
        this.pk_seed = Arrays.clone(pk_seed);

        genPrivateKeyMaterial_cyclic();

        return new RainbowPrivateKeyParameters(this.rainbowParams,
            this.sk_seed, this.s1, this.t1, this.t3, this.t4, this.l1_F1, this.l1_F2,
            this.l2_F1, this.l2_F2, this.l2_F3, this.l2_F5, this.l2_F6, null);
    }
}
