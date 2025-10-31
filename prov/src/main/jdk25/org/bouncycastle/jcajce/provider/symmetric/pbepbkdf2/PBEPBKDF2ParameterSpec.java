package org.bouncycastle.jcajce.provider.symmetric.pbepbkdf2;

import javax.crypto.spec.PBEKeySpec;
import java.security.spec.AlgorithmParameterSpec;

public class PBEPBKDF2ParameterSpec
    extends PBEKeySpec
    implements AlgorithmParameterSpec
{
    public PBEPBKDF2ParameterSpec(char[] password)
    {
        super(password);
    }

    public PBEPBKDF2ParameterSpec(char[] password, byte[] salt, int iterationCount, int keyLength)
    {
        super(password, salt, iterationCount, keyLength);
    }

    public PBEPBKDF2ParameterSpec(char[] password, byte[] salt, int iterationCount)
    {
        super(password, salt, iterationCount);
    }
}
