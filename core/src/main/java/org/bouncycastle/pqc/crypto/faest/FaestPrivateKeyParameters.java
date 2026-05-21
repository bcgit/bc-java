package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * FAEST private key: encoded as {@code owfInput || owfKey} (matching the upstream
 * {@code SK_INPUT || SK_KEY} layout). Length matches {@link FaestParameters#getSkSize()}.
 */
public class FaestPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private final FaestParameters parameters;
    private final byte[] privateKey;

    public FaestPrivateKeyParameters(FaestParameters parameters, byte[] privateKey)
    {
        super(true);
        if (privateKey.length != parameters.getSkSize())
        {
            throw new IllegalArgumentException("private key length must be " + parameters.getSkSize()
                + ", got " + privateKey.length);
        }
        this.parameters = parameters;
        this.privateKey = Arrays.clone(privateKey);
    }

    public byte[] getPrivateKey()
    {
        return Arrays.clone(privateKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(privateKey);
    }

    public FaestParameters getParameters()
    {
        return parameters;
    }

    /** OWF input (the public OWF argument): first {@code owfInputSize} bytes. */
    byte[] getOwfInput()
    {
        return Arrays.copyOfRange(privateKey, 0, parameters.getOwfInputSize());
    }

    /** OWF key (the secret OWF argument): remaining {@code lambda/8} bytes. */
    byte[] getOwfKey()
    {
        return Arrays.copyOfRange(privateKey, parameters.getOwfInputSize(), privateKey.length);
    }
}
