package org.bouncycastle.internal.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/**
 * <a href="https://tools.ietf.org/html/rfc5084">RFC 5084</a>: GCMParameters object.
 * <p>
 * <pre>
 GCMParameters ::= SEQUENCE {
   aes-nonce        OCTET STRING, -- recommended size is 12 octets
   aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
 * </pre>
 */
public class GCMParameters
    extends ASN1Object
{
    private static final int DEFAULT_ICVLEN = 12;

    private byte[] nonce;
    private int icvLen;

    /**
     * Return an GCMParameters object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link GCMParameters} object
     * <li> {@link ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with GCMParameters structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static GCMParameters getInstance(
        Object  obj)
    {
        if (obj instanceof GCMParameters)
        {
            return (GCMParameters)obj;
        }
        else if (obj != null)
        {
            return new GCMParameters(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private GCMParameters(
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

    public GCMParameters(
        byte[] nonce,
        int    icvLen)
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

    // RFC 5084: AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16). The lower bound relaxes to the
    // NIST SP 800-38D minimum of 4 octets (32 bits) when Properties.GCM_ALLOW_SHORT_TAGS is set.
    private static int validateICVLen(int icvLen)
    {
        int minLen = Properties.isOverrideSet(Properties.GCM_ALLOW_SHORT_TAGS) ? 4 : 12;
        if (icvLen < minLen || icvLen > 16)
        {
            throw new IllegalArgumentException("Invalid ICV length: " + icvLen);
        }

        return icvLen;
    }
}
