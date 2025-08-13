package org.bouncycastle.pqc.crypto.mldsa;

import org.bouncycastle.util.Arrays;

public class MLDSAPrivateKeyParameters
    extends MLDSAKeyParameters
{
    public static final int BOTH = 0;
    public static final int SEED_ONLY = 1;
    public static final int EXPANDED_KEY = 2;

    final byte[] rho;
    final byte[] k;
    final byte[] tr;
    final byte[] s1;
    final byte[] s2;
    final byte[] t0;

    private final byte[] t1;
    private final byte[] seed;

    private final int prefFormat;

    public MLDSAPrivateKeyParameters(MLDSAParameters params, byte[] encoding)
    {
        this(params, encoding, null);
    }

    public MLDSAPrivateKeyParameters(MLDSAParameters params, byte[] rho, byte[] K, byte[] tr, byte[] s1, byte[] s2, byte[] t0, byte[] t1)
    {
        this(params, rho, K, tr, s1, s2, t0, t1, null);
    }

    public MLDSAPrivateKeyParameters(MLDSAParameters params, byte[] rho, byte[] K, byte[] tr, byte[] s1, byte[] s2, byte[] t0, byte[] t1, byte[] seed)
    {
        super(true, params);
        this.rho = Arrays.clone(rho);
        this.k = Arrays.clone(K);
        this.tr = Arrays.clone(tr);
        this.s1 = Arrays.clone(s1);
        this.s2 = Arrays.clone(s2);
        this.t0 = Arrays.clone(t0);
        this.t1 = Arrays.clone(t1);
        this.seed = Arrays.clone(seed);
        this.prefFormat = (seed != null) ? BOTH : EXPANDED_KEY;
    }

    public MLDSAPrivateKeyParameters(MLDSAParameters params, byte[] encoding, MLDSAPublicKeyParameters pubKey)
    {
        super(true, params);

        MLDSAEngine eng = params.getEngine(null);
        if (encoding.length == MLDSAEngine.SeedBytes)
        {
            byte[][] keyDetails = eng.generateKeyPairInternal(encoding);

            this.rho = keyDetails[0];
            this.k = keyDetails[1];
            this.tr = keyDetails[2];
            this.s1 = keyDetails[3];
            this.s2 = keyDetails[4];
            this.t0 = keyDetails[5];
            this.t1 = keyDetails[6];
            this.seed = keyDetails[7];
        }
        else
        {
            int index = 0;
            this.rho = Arrays.copyOfRange(encoding, 0, MLDSAEngine.SeedBytes);
            index += MLDSAEngine.SeedBytes;
            this.k = Arrays.copyOfRange(encoding, index, index + MLDSAEngine.SeedBytes);
            index += MLDSAEngine.SeedBytes;
            this.tr = Arrays.copyOfRange(encoding, index, index + MLDSAEngine.TrBytes);
            index += MLDSAEngine.TrBytes;
            int delta = eng.getDilithiumL() * eng.getDilithiumPolyEtaPackedBytes();
            this.s1 = Arrays.copyOfRange(encoding, index, index + delta);
            index += delta;
            delta = eng.getDilithiumK() * eng.getDilithiumPolyEtaPackedBytes();
            this.s2 = Arrays.copyOfRange(encoding, index, index + delta);
            index += delta;
            delta = eng.getDilithiumK() * MLDSAEngine.DilithiumPolyT0PackedBytes;
            this.t0 = Arrays.copyOfRange(encoding, index, index + delta);
            index += delta;
            this.t1 = eng.deriveT1(rho, k, tr, s1, s2, t0);
            this.seed = null;
        }

        if (pubKey != null)
        {
            if (!Arrays.constantTimeAreEqual(this.t1, pubKey.getT1()))
            {
                throw new IllegalArgumentException("passed in public key does not match private values");
            }
        }

        this.prefFormat = (seed != null) ? BOTH : EXPANDED_KEY;
    }

    private MLDSAPrivateKeyParameters(MLDSAPrivateKeyParameters params, int preferredFormat)
    {
        super(true, params.getParameters());

        this.rho = params.rho;
        this.k = params.k;
        this.tr = params.tr;
        this.s1 = params.s1;
        this.s2 = params.s2;
        this.t0 = params.t0;
        this.t1 = params.t1;
        this.seed = params.seed;
        this.prefFormat = preferredFormat;
    }

    public MLDSAPrivateKeyParameters getParametersWithFormat(int format)
    {
        if (this.prefFormat == format)
        {
            return this;
        }

        switch (format)
        {
        case BOTH:
        case SEED_ONLY:
        {
            if (this.seed == null)
            {
                throw new IllegalStateException("no seed available");
            }
            break;
        }
        case EXPANDED_KEY:
            break;
        default:
            throw new IllegalArgumentException("unknown format");
        }

        return new MLDSAPrivateKeyParameters(this, format);
    }

    public int getPreferredFormat()
    {
        return prefFormat;
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(new byte[][]{rho, k, tr, s1, s2, t0});
    }

    public byte[] getK()
    {
        return Arrays.clone(k);
    }

    /**
     * @deprecated Use {@link #getEncoded()} instead.
     */
    @Deprecated
    @SuppressWarnings("InlineMeSuggester")
    public byte[] getPrivateKey()
    {
        return getEncoded();
    }

    public byte[] getPublicKey()
    {
        return MLDSAPublicKeyParameters.getEncoded(rho, t1);
    }

    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }

    public MLDSAPublicKeyParameters getPublicKeyParameters()
    {
        if (this.t1 == null)
        {
            return null;
        }
        
        return new MLDSAPublicKeyParameters(getParameters(), rho, t1);
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
