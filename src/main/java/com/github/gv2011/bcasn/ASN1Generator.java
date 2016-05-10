package com.github.gv2011.bcasn;

import java.io.OutputStream;

public abstract class ASN1Generator
{
    protected OutputStream _out;
    
    public ASN1Generator(OutputStream out)
    {
        _out = out;
    }
    
    public abstract OutputStream getRawOutputStream();
}
