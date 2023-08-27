package org.bouncycastle.pqc.crypto.crystals.dilithium;

import org.bouncycastle.util.Arrays;

public class DilithiumPrivateKeyParameters
    extends DilithiumKeyParameters
{
    final byte[] rho;
    final byte[] k;
    final byte[] tr;
    final byte[] s1;
    final byte[] s2;
    final byte[] t0;

    private final byte[] t1;

    public DilithiumPrivateKeyParameters(DilithiumParameters params, byte[] rho, byte[] K, byte[] tr, byte[] s1, byte[] s2, byte[] t0, byte[] t1)
    {
        super(true, params);
        this.rho = Arrays.clone(rho);
        this.k = Arrays.clone(K);
        this.tr = Arrays.clone(tr);
        this.s1 = Arrays.clone(s1);
        this.s2 = Arrays.clone(s2);
        this.t0 = Arrays.clone(t0);
        this.t1 = Arrays.clone(t1);
    }

    public DilithiumPrivateKeyParameters(DilithiumParameters params, byte[] encoding, DilithiumPublicKeyParameters pubKey)
    {
        super(true, params);

        DilithiumEngine eng = params.getEngine(null);
        int index = 0;
        this.rho = Arrays.copyOfRange(encoding, 0, DilithiumEngine.SeedBytes); index += DilithiumEngine.SeedBytes;
        this.k = Arrays.copyOfRange(encoding, index, index + DilithiumEngine.SeedBytes); index += DilithiumEngine.SeedBytes;
        this.tr = Arrays.copyOfRange(encoding, index, index + DilithiumEngine.TrBytes); index += DilithiumEngine.TrBytes;
        int delta = eng.getDilithiumL() * eng.getDilithiumPolyEtaPackedBytes();
        this.s1 = Arrays.copyOfRange(encoding, index, index + delta); index += delta;
        delta = eng.getDilithiumK() * eng.getDilithiumPolyEtaPackedBytes();
        this.s2 = Arrays.copyOfRange(encoding, index, index + delta); index += delta;
        delta = eng.getDilithiumK() * DilithiumEngine.DilithiumPolyT0PackedBytes;
        this.t0 = Arrays.copyOfRange(encoding, index, index + delta); index += delta;

        if (pubKey != null)
        {
            this.t1 = pubKey.getT1();
        }
        else
        {
            this.t1 = null;
        }
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(new byte[][]{ rho, k, tr, s1, s2, t0 });
    }

    public byte[] getK()
    {
        return Arrays.clone(k);
    }

    /** @deprecated Use {@link #getEncoded()} instead. */
    public byte[] getPrivateKey()
    {
        return getEncoded();
    }

    public byte[] getPublicKey()
    {
        return DilithiumPublicKeyParameters.getEncoded(rho, t1);
    }

    public DilithiumPublicKeyParameters getPublicKeyParameters()
    {
        return new DilithiumPublicKeyParameters(getParameters(), rho, t1);
    }

    public byte[] getRho()
    {
        return Arrays.clone(rho);
    }

    public byte[] getS1()
    {
        return Arrays.clone(s1);
    }

    public byte[] getS2()
    {
        return Arrays.clone(s2);
    }

    public byte[] getT0()
    {
        return Arrays.clone(t0);
    }

    public byte[] getT1()
    {
        return Arrays.clone(t1);
    }

    public byte[] getTr()
    {
        return Arrays.clone(tr);
    }
}
