package org.bouncycastle.pqc.crypto.frodo;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class FrodoParameters
{

    private int n;

    private boolean isAES128; // else SHAKE128

    private FrodoEngine engine;

    public FrodoParameters(int n, boolean isAES128) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException
    {
        this.n = n;
        this.isAES128 = isAES128;
        this.engine = new FrodoEngine(n, isAES128);
    }

    FrodoEngine getEngine()
    {
        return engine;
    }

    public int getN()
    {
        return n;
    }

    public boolean isAES128()
    {
        return isAES128;
    }
}
