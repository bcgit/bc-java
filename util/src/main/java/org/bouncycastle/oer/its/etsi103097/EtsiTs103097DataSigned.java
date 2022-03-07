package org.bouncycastle.oer.its.etsi103097;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

/**
 * EtsiTs103097Data-Signed {ToBeSignedDataContent} ::= EtsiTs103097Data (WITH COMPONENTS {...,
 * content (WITH COMPONENTS {
 * signedData (WITH COMPONENTS {...,
 * tbsData (WITH COMPONENTS {
 * payload (WITH COMPONENTS {
 * data (WITH COMPONENTS {...,
 * content (WITH COMPONENTS {
 * unsecuredData (CONTAINING ToBeSignedDataContent)
 * })
 * }) PRESENT
 * })
 * })
 * })
 * })
 * })
 */
public class EtsiTs103097DataSigned
    extends EtsiTs103097Data
{
    public EtsiTs103097DataSigned(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected EtsiTs103097DataSigned(ASN1Sequence src)
    {
        super(src);
    }

    public static EtsiTs103097DataSigned getInstance(Object o)
    {
        if (o instanceof EtsiTs103097DataSigned)
        {
            return (EtsiTs103097DataSigned)o;
        }
        if (o != null)
        {
            return new EtsiTs103097DataSigned(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
