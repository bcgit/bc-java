package org.bouncycastle.crypto.threshold;

public interface SplitSecret
{
    SecretShare[] getSecretShare();

    byte[] recombine();
}
