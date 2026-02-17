package org.bouncycastle.jcajce.spec;

import javax.crypto.spec.PBEKeySpec;
import java.security.spec.AlgorithmParameterSpec;

public class PBKDF2ParameterSpec
    extends PBEKeySpec
    implements AlgorithmParameterSpec
{
    public PBKDF2ParameterSpec(char[] password)
    {
        super(password);
    }

    public PBKDF2ParameterSpec(char[] password, byte[] salt, int iterationCount, int keyLength)
    {
        super(password, salt, iterationCount, keyLength);
    }

    public PBKDF2ParameterSpec(char[] password, byte[] salt, int iterationCount)
    {
        super(password, salt, iterationCount);
    }
}
