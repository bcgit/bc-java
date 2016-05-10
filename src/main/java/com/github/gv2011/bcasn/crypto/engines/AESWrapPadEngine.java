package com.github.gv2011.bcasn.crypto.engines;

public class AESWrapPadEngine
    extends RFC5649WrapEngine
{
    public AESWrapPadEngine()
    {
        super(new AESEngine());
    }
}
