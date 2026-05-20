package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * FAEST public key: encoded as {@code owfInput || owfOutput}.
 * Length matches {@link FaestParameters#getPkSize()}.
 */
public class FaestPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final FaestParameters parameters;
    private final byte[] publicKey;

    public FaestPublicKeyParameters(FaestParameters parameters, byte[] publicKey)
    {
        super(false);
        if (publicKey.length != parameters.getPkSize())
        {
            throw new IllegalArgumentException("public key length must be " + parameters.getPkSize()
                + ", got " + publicKey.length);
        }
        this.parameters = parameters;
        this.publicKey = Arrays.clone(publicKey);
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(publicKey);
    }

    public FaestParameters getParameters()
    {
        return parameters;
    }

    /** OWF input (the public OWF argument): first {@code owfInputSize} bytes. */
    byte[] getOwfInput()
    {
        return Arrays.copyOfRange(publicKey, 0, parameters.getOwfInputSize());
    }

    /** OWF output (the public OWF image): remaining bytes after the input. */
    byte[] getOwfOutput()
    {
        return Arrays.copyOfRange(publicKey, parameters.getOwfInputSize(), publicKey.length);
    }
}
