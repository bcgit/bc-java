package org.bouncycastle.oer.its;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;

public class SubjectAssurance
    extends DEROctetString
{

    public SubjectAssurance(byte[] string)
    {
        super(string);
    }


    public SubjectAssurance(ASN1Encodable obj)
        throws IOException
    {
        super(obj);
    }

    public static SubjectAssurance getInstance(Object o)
    {
        if (o instanceof SubjectAssurance)
        {
            return (SubjectAssurance)o;
        }
        else
        {
            return new SubjectAssurance(DEROctetString.getInstance(o).getOctets());
        }
    }
}
