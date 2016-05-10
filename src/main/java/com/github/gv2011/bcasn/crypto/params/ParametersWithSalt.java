package com.github.gv2011.bcasn.crypto.params;

import com.github.gv2011.bcasn.crypto.CipherParameters;

/**
 * Cipher parameters with a fixed salt value associated with them.
 */
public class ParametersWithSalt
    implements CipherParameters
{
    private byte[]              salt;
    private CipherParameters    parameters;

    public ParametersWithSalt(
        CipherParameters    parameters,
        byte[]              salt)
    {
        this(parameters, salt, 0, salt.length);
    }

    public ParametersWithSalt(
        CipherParameters    parameters,
        byte[]              salt,
        int                 saltOff,
        int                 saltLen)
    {
        this.salt = new byte[saltLen];
        this.parameters = parameters;

        System.arraycopy(salt, saltOff, this.salt, 0, saltLen);
    }

    public byte[] getSalt()
    {
        return salt;
    }

    public CipherParameters getParameters()
    {
        return parameters;
    }
}
