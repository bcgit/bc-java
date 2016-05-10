package com.github.gv2011.bcasn.asn1.misc;

import com.github.gv2011.bcasn.asn1.DERIA5String;

public class VerisignCzagExtension
    extends DERIA5String
{
    public VerisignCzagExtension(
        DERIA5String str)
    {
        super(str.getString());
    }

    public String toString()
    {
        return "VerisignCzagExtension: " + this.getString();
    }
}
