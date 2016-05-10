package com.github.gv2011.bcasn.asn1.misc;

import com.github.gv2011.bcasn.asn1.DERIA5String;

public class NetscapeRevocationURL
    extends DERIA5String
{
    public NetscapeRevocationURL(
        DERIA5String str)
    {
        super(str.getString());
    }

    public String toString()
    {
        return "NetscapeRevocationURL: " + this.getString();
    }
}
