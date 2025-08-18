package org.bouncycastle.pqc.crypto.mlkem;

import org.bouncycastle.util.Arrays;

public class MLKEMPublicKeyParameters
    extends MLKEMKeyParameters
{
    static byte[] getEncoded(byte[] t, byte[] rho)
    {
        return Arrays.concatenate(t, rho);
    }

    final byte[] t;
    final byte[] rho;

    public MLKEMPublicKeyParameters(MLKEMParameters params, byte[] t, byte[] rho)
    {
        super(false, params);

        MLKEMEngine engine = params.getEngine();

        if (t.length != engine.getKyberPolyVecBytes())
        {
            throw new IllegalArgumentException("'t' has invalid length");
        }
        if (rho.length != MLKEMEngine.KyberSymBytes)
        {
            throw new IllegalArgumentException("'rho' has invalid length");
        }

        this.t = Arrays.clone(t);
        this.rho = Arrays.clone(rho);

        if (!engine.checkModulus(this.t))
        {
            throw new IllegalArgumentException("Modulus check failed for ML-KEM public key");
        }
    }

    public MLKEMPublicKeyParameters(MLKEMParameters params, byte[] encoding)
    {
        super(false, params);

        MLKEMEngine engine = params.getEngine();

        if (encoding.length != engine.getKyberIndCpaPublicKeyBytes())
        {
            throw new IllegalArgumentException("'encoding' has invalid length");
        }

        this.t = Arrays.copyOfRange(encoding, 0, encoding.length - MLKEMEngine.KyberSymBytes);
        this.rho = Arrays.copyOfRange(encoding, encoding.length - MLKEMEngine.KyberSymBytes, encoding.length);

        if (!engine.checkModulus(this.t))
        {
            throw new IllegalArgumentException("Modulus check failed for ML-KEM public key");
        }
    }

    public byte[] getEncoded()
    {
        return getEncoded(t, rho);
    }

    public byte[] getRho()
    {
        return Arrays.clone(rho);
    }

    public byte[] getT()
    {
        return Arrays.clone(t);
    }
}
