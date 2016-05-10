package com.github.gv2011.bcasn.asn1.crmf;

import com.github.gv2011.bcasn.asn1.ASN1Encodable;
import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.asn1.DERUTF8String;
import com.github.gv2011.bcasn.asn1.pkcs.PrivateKeyInfo;
import com.github.gv2011.bcasn.asn1.x509.GeneralName;

public class EncKeyWithID
    extends ASN1Object
{
    private final PrivateKeyInfo privKeyInfo;
    private final ASN1Encodable identifier;

    public static EncKeyWithID getInstance(Object o)
    {
        if (o instanceof EncKeyWithID)
        {
            return (EncKeyWithID)o;
        }
        else if (o != null)
        {
            return new EncKeyWithID(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private EncKeyWithID(ASN1Sequence seq)
    {
        this.privKeyInfo = PrivateKeyInfo.getInstance(seq.getObjectAt(0));

        if (seq.size() > 1)
        {
            if (!(seq.getObjectAt(1) instanceof DERUTF8String))
            {
                this.identifier = GeneralName.getInstance(seq.getObjectAt(1));
            }
            else
            {
                this.identifier = (ASN1Encodable)seq.getObjectAt(1);
            }
        }
        else
        {
            this.identifier = null;
        }
    }

    public EncKeyWithID(PrivateKeyInfo privKeyInfo)
    {
        this.privKeyInfo = privKeyInfo;
        this.identifier = null;
    }

    public EncKeyWithID(PrivateKeyInfo privKeyInfo, DERUTF8String str)
    {
        this.privKeyInfo = privKeyInfo;
        this.identifier = str;
    }

    public EncKeyWithID(PrivateKeyInfo privKeyInfo, GeneralName generalName)
    {
        this.privKeyInfo = privKeyInfo;
        this.identifier = generalName;
    }

    public PrivateKeyInfo getPrivateKey()
    {
        return privKeyInfo;
    }

    public boolean hasIdentifier()
    {
        return identifier != null;
    }

    public boolean isIdentifierUTF8String()
    {
        return identifier instanceof DERUTF8String;
    }

    public ASN1Encodable getIdentifier()
    {
        return identifier;
    }
    
    /**
     * <pre>
     * EncKeyWithID ::= SEQUENCE {
     *      privateKey           PrivateKeyInfo,
     *      identifier CHOICE {
     *         string               UTF8String,
     *         generalName          GeneralName
     *     } OPTIONAL
     * }
     * </pre>
     * @return a DERSequence representing the value in this object.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(privKeyInfo);

        if (identifier != null)
        {
            v.add(identifier);
        }

        return new DERSequence(v);
    }
}
