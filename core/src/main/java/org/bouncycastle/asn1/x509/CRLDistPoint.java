package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Strings;

public class CRLDistPoint
    extends ASN1Object
{
    ASN1Sequence  seq = null;

    public static CRLDistPoint getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CRLDistPoint getInstance(
        Object  obj)
    {
        if (obj instanceof CRLDistPoint)
        {
            return (CRLDistPoint)obj;
        }
        else if (obj != null)
        {
            return new CRLDistPoint(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static CRLDistPoint fromExtensions(Extensions extensions)
    {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.cRLDistributionPoints));
    }

    private CRLDistPoint(
        ASN1Sequence seq)
    {
        this.seq = seq;
    }
    
    public CRLDistPoint(
        DistributionPoint[] points)
    {
        seq = new DERSequence(points);
    }

    /**
     * Return the distribution points making up the sequence.
     * 
     * @return DistributionPoint[]
     */
    public DistributionPoint[] getDistributionPoints()
    {
        DistributionPoint[]    dp = new DistributionPoint[seq.size()];
        
        for (int i = 0; i != seq.size(); i++)
        {
            dp[i] = DistributionPoint.getInstance(seq.getObjectAt(i));
        }
        
        return dp;
    }
    
    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * CRLDistPoint ::= SEQUENCE SIZE {1..MAX} OF DistributionPoint
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return seq;
    }

    public String toString()
    {
        StringBuilder buf = new StringBuilder();
        String       sep = Strings.lineSeparator();

        buf.append("CRLDistPoint:");
        buf.append(sep);
        DistributionPoint dp[] = getDistributionPoints();
        for (int i = 0; i != dp.length; i++)
        {
            buf.append("    ");
            buf.append(dp[i]);
            buf.append(sep);
        }
        return buf.toString();
    }
}
