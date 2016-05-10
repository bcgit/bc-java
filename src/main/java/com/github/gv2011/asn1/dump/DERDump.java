package com.github.gv2011.asn1.dump;

import com.github.gv2011.asn1.ASN1Encodable;
import com.github.gv2011.asn1.ASN1Primitive;

/**
 * @deprecated use ASN1Dump.
 */
public class DERDump
    extends ASN1Dump
{
    /**
     * dump out a DER object as a formatted string
     *
     * @param obj the ASN1Primitive to be dumped out.
     */
    public static String dumpAsString(
        ASN1Primitive obj)
    {
        StringBuffer buf = new StringBuffer();

        _dumpAsString("", false, obj, buf);

        return buf.toString();
    }

    /**
     * dump out a DER object as a formatted string
     *
     * @param obj the ASN1Primitive to be dumped out.
     */
    public static String dumpAsString(
        ASN1Encodable obj)
    {
        StringBuffer buf = new StringBuffer();

        _dumpAsString("", false, obj.toASN1Primitive(), buf);

        return buf.toString();
    }
}
