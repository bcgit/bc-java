package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;

public class PKCS7ProcessableObject
    implements CMSTypedData
{
    private final ASN1ObjectIdentifier type;
    private final ASN1Encodable structure;

    public PKCS7ProcessableObject(
        ASN1ObjectIdentifier type,
        ASN1Encodable structure)
    {
        this.type = type;
        this.structure = structure;
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return type;
    }

    public void write(OutputStream cOut)
        throws IOException, CMSException
    {
        if (structure instanceof ASN1Sequence)
        {
            ASN1Sequence s = ASN1Sequence.getInstance(structure);

            for (Iterator it = s.iterator(); it.hasNext();)
            {
                ASN1Encodable enc = (ASN1Encodable)it.next();

                cOut.write(enc.toASN1Primitive().getEncoded(ASN1Encoding.DER));
            }
        }
        else
        {
            byte[] encoded = structure.toASN1Primitive().getEncoded(ASN1Encoding.DER);
            int index = 1;

            while ((encoded[index] & 0xff) > 127)
            {
                index++;
            }

            index++;

            cOut.write(encoded, index, encoded.length - index);
        }
    }

    public Object getContent()
    {
        return structure;
    }
}
