package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 * <a href="https://tools.ietf.org/html/rfc5084">RFC 5084</a>: CCMParameters object.
 * <p>
 * <pre>
 CCMParameters ::= SEQUENCE {
   aes-nonce        OCTET STRING, -- recommended size is 12 octets
   aes-ICVlen       AES-CCM-ICVlen DEFAULT 12 }
 * </pre>
 */
public class CCMParameters
    extends ASN1Object
{
    private static final int DEFAULT_ICVLEN = 12;

    private byte[] nonce;
    private int icvLen;

    /**
     * Return an CCMParameters object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link org.bouncycastle.asn1.cms.CCMParameters} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with CCMParameters structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static CCMParameters getInstance(
        Object  obj)
    {
        if (obj instanceof CCMParameters)
        {
            return (CCMParameters)obj;
        }
        else if (obj != null)
        {
            return new CCMParameters(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private CCMParameters(
        ASN1Sequence seq)
    {
        int count = seq.size();
        if (count < 1 || count > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + count);
        }

        this.nonce = ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets();
        ASN1Integer icvLen = seq.size() < 2 ? null : ASN1Integer.getInstance(seq.getObjectAt(1)); 

        this.icvLen = validateICVLen(icvLen == null ? DEFAULT_ICVLEN : icvLen.intValueExact());
    }

    public CCMParameters(
        byte[] nonce,
        int icvLen)
    {
        this.nonce = Arrays.clone(nonce);
        this.icvLen = validateICVLen(icvLen);
    }

    public byte[] getNonce()
    {
        return Arrays.clone(nonce);
    }

    public int getIcvLen()
    {
        return icvLen;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(new DEROctetString(nonce));

        if (icvLen != DEFAULT_ICVLEN)
        {
            v.add(ASN1Integer.valueOf(icvLen));
        }

        return new DERSequence(v);
    }

    // RFC 5084: AES-CCM-ICVlen ::= INTEGER (4 | 6 | 8 | 10 | 12 | 14 | 16)
    private static int validateICVLen(int icvLen)
    {
        if (icvLen < 4 || icvLen > 16 || (icvLen & 1) != 0)
            throw new IllegalArgumentException("Invalid ICV length: " + icvLen);

        return icvLen;
    }    
}
