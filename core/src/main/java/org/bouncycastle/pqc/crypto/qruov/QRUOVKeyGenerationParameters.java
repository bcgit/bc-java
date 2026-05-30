package org.bouncycastle.pqc.crypto.qruov;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class QRUOVKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final QRUOVParameters params;

    public QRUOVKeyGenerationParameters(SecureRandom random, QRUOVParameters qruovParameters)
    {
        super(random, 256);
        this.params = qruovParameters;
    }

    public QRUOVParameters getParameters()
    {
        return params;
    }
}
