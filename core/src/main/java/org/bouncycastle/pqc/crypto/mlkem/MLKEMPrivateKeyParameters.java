package org.bouncycastle.pqc.crypto.mlkem;

import org.bouncycastle.util.Arrays;

public class MLKEMPrivateKeyParameters
    extends MLKEMKeyParameters
{
    public static final int BOTH = 0;
    public static final int SEED_ONLY = 1;
    public static final int EXPANDED_KEY = 2;

    final byte[] s;
    final byte[] hpk;
    final byte[] nonce;
    final byte[] t;
    final byte[] rho;
    final byte[] seed;

    private final int prefFormat;

    public MLKEMPrivateKeyParameters(MLKEMParameters params, byte[] s, byte[] hpk, byte[] nonce, byte[] t, byte[] rho)
    {
        this(params, s, hpk, nonce, t, rho, null);
    }

    public MLKEMPrivateKeyParameters(MLKEMParameters params, byte[] s, byte[] hpk, byte[] nonce, byte[] t, byte[] rho, byte[] seed)
    {
        super(true, params);

        this.s = Arrays.clone(s);
        this.hpk = Arrays.clone(hpk);
        this.nonce = Arrays.clone(nonce);
        this.t = Arrays.clone(t);
        this.rho = Arrays.clone(rho);
        this.seed = Arrays.clone(seed);
        this.prefFormat = BOTH;
    }

    public MLKEMPrivateKeyParameters(MLKEMParameters params, byte[] encoding)
    {
        this(params, encoding, null);
    }

    public MLKEMPrivateKeyParameters(MLKEMParameters params, byte[] encoding, MLKEMPublicKeyParameters pubKey)
    {
        super(true, params);

        MLKEMEngine eng = params.getEngine();
        if (encoding.length == MLKEMEngine.KyberSymBytes * 2)
        {
            byte[][] keyData = eng.generateKemKeyPairInternal(
                Arrays.copyOfRange(encoding, 0, MLKEMEngine.KyberSymBytes),
                Arrays.copyOfRange(encoding, MLKEMEngine.KyberSymBytes, encoding.length));
            this.s = keyData[2];
            this.hpk = keyData[3];
            this.nonce = keyData[4];
            this.t = keyData[0];
            this.rho = keyData[1];
            this.seed = keyData[5];
        }
        else
        {
            int index = 0;
            this.s = Arrays.copyOfRange(encoding, 0, eng.getKyberIndCpaSecretKeyBytes());
            index += eng.getKyberIndCpaSecretKeyBytes();
            this.t = Arrays.copyOfRange(encoding, index, index + eng.getKyberIndCpaPublicKeyBytes() - MLKEMEngine.KyberSymBytes);
            index += eng.getKyberIndCpaPublicKeyBytes() - MLKEMEngine.KyberSymBytes;
            this.rho = Arrays.copyOfRange(encoding, index, index + 32);
            index += 32;
            this.hpk = Arrays.copyOfRange(encoding, index, index + 32);
            index += 32;
            this.nonce = Arrays.copyOfRange(encoding, index, index + MLKEMEngine.KyberSymBytes);
            this.seed = null;
        }

        if (pubKey != null)
        {
            if (!Arrays.constantTimeAreEqual(this.t, pubKey.t) || !Arrays.constantTimeAreEqual(this.rho, pubKey.rho))
            {
                throw new IllegalArgumentException("passed in public key does not match private values");
            }
        }

        this.prefFormat = (seed == null) ? EXPANDED_KEY : BOTH;
    }

    private MLKEMPrivateKeyParameters(MLKEMPrivateKeyParameters params, int preferredFormat)
    {
        super(true, params.getParameters());

        this.s = params.s;
        this.t = params.t;
        this.rho = params.rho;
        this.hpk = params.hpk;
        this.nonce = params.nonce;
        this.seed = params.seed;
        this.prefFormat = preferredFormat;
    }

    public MLKEMPrivateKeyParameters getParametersWithFormat(int format)
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

        return new MLKEMPrivateKeyParameters(this, format);
    }

    public int getPreferredFormat()
    {
        return prefFormat;
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(new byte[][]{ s, t, rho, hpk, nonce });
    }

    public byte[] getHPK()
    {
        return Arrays.clone(hpk);
    }

    public byte[] getNonce()
    {
        return Arrays.clone(nonce);
    }

    public byte[] getPublicKey()
    {
        return MLKEMPublicKeyParameters.getEncoded(t, rho);
    }

    public MLKEMPublicKeyParameters getPublicKeyParameters()
    {
        return new MLKEMPublicKeyParameters(getParameters(), t, rho);
    }

    public byte[] getRho()
    {
        return Arrays.clone(rho);
    }

    public byte[] getS()
    {
        return Arrays.clone(s);
    }

    public byte[] getT()
    {
        return Arrays.clone(t);
    }

    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }
}
