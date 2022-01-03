package org.bouncycastle.pqc.crypto.frodo;

public class FrodoKEMParameters
{
    // SHAKE



    // AES


    private FrodoKEMEngine engine;
    private FrodoKEMParameters(FrodoKEMEngine engine)
    {
        this.engine = engine;
    }

    FrodoKEMEngine getEngine()
    {
        return engine;
    }
}
