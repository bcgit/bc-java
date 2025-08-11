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

        validatePublicKey(params.getEngine(), getEncoded(t, rho));

        this.t = Arrays.clone(t);
        this.rho = Arrays.clone(rho);
    }

    public MLKEMPublicKeyParameters(MLKEMParameters params, byte[] encoding)
    {
        super(false, params);

        validatePublicKey(params.getEngine(), encoding);

        this.t = Arrays.copyOfRange(encoding, 0, encoding.length - MLKEMEngine.KyberSymBytes);
        this.rho = Arrays.copyOfRange(encoding, encoding.length - MLKEMEngine.KyberSymBytes, encoding.length);
    }

    private static void validatePublicKey(MLKEMEngine engine, byte[] publicKeyInput)
    {
        // Input validation (6.2 ML-KEM Encaps)
        // length Check
        if (publicKeyInput.length != engine.getKyberIndCpaPublicKeyBytes())
        {
            throw new IllegalArgumentException("length check failed for ml-kem public key construction");
        }

        // Modulus Check
        PolyVec polyVec = new PolyVec(engine);
        MLKEMIndCpa indCpa = engine.getIndCpa();

        byte[] seed = indCpa.unpackPublicKey(polyVec, publicKeyInput);
        byte[] ek = indCpa.packPublicKey(polyVec, seed);
        if (!Arrays.areEqual(ek, publicKeyInput))
        {
            throw new IllegalArgumentException("modulus check failed for ml-kem public key construction");
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
