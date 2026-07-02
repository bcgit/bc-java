package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.signers.mldsa.MLDSAEngine;
import org.bouncycastle.util.Arrays;

public class MLDSAPublicKeyParameters
    extends MLDSAKeyParameters
{
    static byte[] getEncoded(byte[] rho, byte[] t1)
    {
        return Arrays.concatenate(rho, t1);
    }

    final byte[] rho;
    final byte[] t1;

    public MLDSAPublicKeyParameters(MLDSAParameters params, byte[] encoding)
    {
        super(false, params);

        MLDSAEngine engine = MLDSAEngine.getInstance(params, null);
        if (encoding.length != MLDSAEngine.SeedBytes + engine.getDilithiumK() * MLDSAEngine.DilithiumPolyT1PackedBytes)
        {
            throw new IllegalArgumentException("'encoding' has invalid length");
        }

        this.rho = Arrays.copyOfRange(encoding, 0, MLDSAEngine.SeedBytes);
        this.t1 = Arrays.copyOfRange(encoding, MLDSAEngine.SeedBytes, encoding.length);
    }

    public MLDSAPublicKeyParameters(MLDSAParameters params, byte[] rho, byte[] t1)
    {
        super(false, params);
        if (rho == null)
        {
            throw new NullPointerException("rho cannot be null");
        }
        if (t1 == null)
        {
            throw new NullPointerException("t1 cannot be null");
        }
        this.rho = Arrays.clone(rho);
        this.t1 = Arrays.clone(t1);
    }

    public byte[] getEncoded()
    {
        return getEncoded(rho, t1);
    }

    public byte[] getRho()
    {
        return Arrays.clone(rho);
    }

    public byte[] getT1()
    {
        return Arrays.clone(t1);
    }
}
