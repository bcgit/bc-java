package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.util.Arrays;

public class RainbowPrivateKeyParameters
    extends RainbowKeyParameters
{
    final byte[] sk_seed;
    final short[][] s1;
    final short[][] t1;
    final short[][] t3;
    final short[][] t4;
    final short[][][] l1_F1;
    final short[][][] l1_F2;
    final short[][][] l2_F1;
    final short[][][] l2_F2;
    final short[][][] l2_F3;
    final short[][][] l2_F5;
    final short[][][] l2_F6;
    private final byte[] pk_seed;
    private byte[] pk_encoded;

    RainbowPrivateKeyParameters(RainbowParameters params,
                                       byte[] sk_seed, short[][] s1,
                                       short[][] t1, short[][] t3, short[][] t4,
                                       short[][][] l1_F1, short[][][] l1_F2,
                                       short[][][] l2_F1, short[][][] l2_F2,
                                       short[][][] l2_F3, short[][][] l2_F5, short[][][] l2_F6,
                                       byte[] pk_encoded)
    {
        super(true, params);

        this.pk_seed = null;
        this.pk_encoded = pk_encoded;
        this.sk_seed = sk_seed.clone();
        this.s1 = RainbowUtil.cloneArray(s1);
        this.t1 = RainbowUtil.cloneArray(t1);
        this.t3 = RainbowUtil.cloneArray(t3);
        this.t4 = RainbowUtil.cloneArray(t4);
        this.l1_F1 = RainbowUtil.cloneArray(l1_F1);
        this.l1_F2 = RainbowUtil.cloneArray(l1_F2);
        this.l2_F1 = RainbowUtil.cloneArray(l2_F1);
        this.l2_F2 = RainbowUtil.cloneArray(l2_F2);
        this.l2_F3 = RainbowUtil.cloneArray(l2_F3);
        this.l2_F5 = RainbowUtil.cloneArray(l2_F5);
        this.l2_F6 = RainbowUtil.cloneArray(l2_F6);
    }

    RainbowPrivateKeyParameters(RainbowParameters params,
                                byte[] pk_seed, byte[] sk_seed, byte[] pk_encoded)
    {
        super(true, params);

        RainbowPrivateKeyParameters expandedPrivKey = new RainbowKeyComputation(params, pk_seed, sk_seed).generatePrivateKey();

        this.pk_seed = pk_seed;
        this.pk_encoded = pk_encoded;
        this.sk_seed = sk_seed;
        this.s1 = expandedPrivKey.s1;
        this.t1 = expandedPrivKey.t1;
        this.t3 = expandedPrivKey.t3;
        this.t4 = expandedPrivKey.t4;
        this.l1_F1 = expandedPrivKey.l1_F1;
        this.l1_F2 = expandedPrivKey.l1_F2;
        this.l2_F1 = expandedPrivKey.l2_F1;
        this.l2_F2 = expandedPrivKey.l2_F2;
        this.l2_F3 = expandedPrivKey.l2_F3;
        this.l2_F5 = expandedPrivKey.l2_F5;
        this.l2_F6 = expandedPrivKey.l2_F6;
    }

    public RainbowPrivateKeyParameters(RainbowParameters params, byte[] encoding)
    {
        super(true, params);

        if (params.getVersion() == Version.COMPRESSED)
        {
            this.pk_seed = Arrays.copyOfRange(encoding, 0, params.getLen_pkseed());
            this.sk_seed = Arrays.copyOfRange(encoding, params.getLen_pkseed(), params.getLen_pkseed() + params.getLen_skseed());

            RainbowPrivateKeyParameters expandedPrivKey = new RainbowKeyComputation(params, pk_seed, sk_seed).generatePrivateKey();

            this.pk_encoded = expandedPrivKey.pk_encoded;
            this.s1 = expandedPrivKey.s1;
            this.t1 = expandedPrivKey.t1;
            this.t3 = expandedPrivKey.t3;
            this.t4 = expandedPrivKey.t4;
            this.l1_F1 = expandedPrivKey.l1_F1;
            this.l1_F2 = expandedPrivKey.l1_F2;
            this.l2_F1 = expandedPrivKey.l2_F1;
            this.l2_F2 = expandedPrivKey.l2_F2;
            this.l2_F3 = expandedPrivKey.l2_F3;
            this.l2_F5 = expandedPrivKey.l2_F5;
            this.l2_F6 = expandedPrivKey.l2_F6;
        }
        else
        {
            int v1 = params.getV1();
            int o1 = params.getO1();
            int o2 = params.getO2();

            this.s1 = new short[o1][o2];
            this.t1 = new short[v1][o1];
            this.t4 = new short[v1][o2];
            this.t3 = new short[o1][o2];
            this.l1_F1 = new short[o1][v1][v1];
            this.l1_F2 = new short[o1][v1][o1];
            this.l2_F1 = new short[o2][v1][v1];
            this.l2_F2 = new short[o2][v1][o1];
            this.l2_F3 = new short[o2][v1][o2];
            this.l2_F5 = new short[o2][o1][o1];
            this.l2_F6 = new short[o2][o1][o2];

            int cnt = 0;
            pk_seed = null;
            sk_seed = Arrays.copyOfRange(encoding, cnt, params.getLen_skseed());
            cnt += sk_seed.length;

            cnt += RainbowUtil.loadEncoded(this.s1, encoding, cnt);
            cnt += RainbowUtil.loadEncoded(this.t1, encoding, cnt);
            cnt += RainbowUtil.loadEncoded(this.t4, encoding, cnt);
            cnt += RainbowUtil.loadEncoded(this.t3, encoding, cnt);

            cnt += RainbowUtil.loadEncoded(this.l1_F1, encoding, cnt, true);
            cnt += RainbowUtil.loadEncoded(this.l1_F2, encoding, cnt, false);
            cnt += RainbowUtil.loadEncoded(this.l2_F1, encoding, cnt, true);
            cnt += RainbowUtil.loadEncoded(this.l2_F2, encoding, cnt, false);
            cnt += RainbowUtil.loadEncoded(this.l2_F3, encoding, cnt, false);
            cnt += RainbowUtil.loadEncoded(this.l2_F5, encoding, cnt, true);
            cnt += RainbowUtil.loadEncoded(this.l2_F6, encoding, cnt, false);

            this.pk_encoded = Arrays.copyOfRange(encoding, cnt, encoding.length);
        }
    }

    byte[] getSk_seed()
    {
        return Arrays.clone(sk_seed);
    }

    short[][] getS1()
    {
        return RainbowUtil.cloneArray(s1);
    }

    short[][] getT1()
    {
        return RainbowUtil.cloneArray(t1);
    }

    short[][] getT4()
    {
        return RainbowUtil.cloneArray(t4);
    }

    short[][] getT3()
    {
        return RainbowUtil.cloneArray(t3);
    }

    short[][][] getL1_F1()
    {
        return RainbowUtil.cloneArray(l1_F1);
    }

    short[][][] getL1_F2()
    {
        return RainbowUtil.cloneArray(l1_F2);
    }

    short[][][] getL2_F1()
    {
        return RainbowUtil.cloneArray(l2_F1);
    }

    short[][][] getL2_F2()
    {
        return RainbowUtil.cloneArray(l2_F2);
    }

    short[][][] getL2_F3()
    {
        return RainbowUtil.cloneArray(l2_F3);
    }
    short[][][] getL2_F5()
    {
        return RainbowUtil.cloneArray(l2_F5);
    }

    short[][][] getL2_F6()
    {
        return RainbowUtil.cloneArray(l2_F6);
    }

    public byte[] getPrivateKey()
    {
        if (getParameters().getVersion() == Version.COMPRESSED)
        {
            return Arrays.concatenate(this.pk_seed, this.sk_seed);
        }

        byte[] ret = sk_seed;
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.s1));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.t1));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.t4));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.t3));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l1_F1, true));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l1_F2, false));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l2_F1, true));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l2_F2, false));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l2_F3, false));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l2_F5, true));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l2_F6, false));
        return ret;
    }

    public byte[] getEncoded()
    {
        if (getParameters().getVersion() == Version.COMPRESSED)
        {
            return Arrays.concatenate(this.pk_seed, this.sk_seed);
        }

        return Arrays.concatenate(getPrivateKey(), pk_encoded);
    }

    public byte[] getPublicKey()
    {
        return pk_encoded;
    }
}
