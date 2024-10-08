package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.S2K;

public abstract class AEADSecretKeyEncryptorBuilderProvider
{

    public abstract AEADSecretKeyEncryptorBuilder get(
            int aeadAlgorithm,
            int symmetricAlgorithm,
            S2K.Argon2Params argon2Params);
}
