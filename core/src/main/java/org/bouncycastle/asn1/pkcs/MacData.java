package org.bouncycastle.asn1.pkcs;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.util.Arrays;

public class MacData
    extends ASN1Object
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    DigestInfo                  digInfo;
    byte[]                      salt;
    BigInteger                  iterationCount;

    public static MacData getInstance(
        Object  obj)
    {
        if (obj instanceof MacData)
        {
            return (MacData)obj;
        }
        else if (obj != null)
        {
            return new MacData(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private MacData(
        ASN1Sequence seq)
    {
        this.digInfo = DigestInfo.getInstance(seq.getObjectAt(0));

        this.salt = Arrays.clone(((ASN1OctetString)seq.getObjectAt(1)).getOctets());

        if (seq.size() == 3)
        {
            this.iterationCount = ((ASN1Integer)seq.getObjectAt(2)).getValue();
        }
        else
        {
            this.iterationCount = ONE;
        }
    }

    public MacData(
        DigestInfo  digInfo,
        byte[]      salt,
        int         iterationCount)
    {
        this.digInfo = digInfo;
        this.salt = Arrays.clone(salt);
        this.iterationCount = BigInteger.valueOf(iterationCount);
    }

    public DigestInfo getMac()
    {
        return digInfo;
    }

    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    public BigInteger getIterationCount()
    {
        return iterationCount;
    }

    /**
     * <pre>
     * MacData ::= SEQUENCE {
     *     mac      DigestInfo,
     *     macSalt  OCTET STRING,
     *     iterations INTEGER DEFAULT 1
     *     -- Note: The default is for historic reasons and its use is deprecated. A
     *     -- higher value, like 1024 is recommended.
     * </pre>
     * @return the basic ASN1Primitive construction.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(digInfo);
        v.add(new DEROctetString(salt));
        
        if (!iterationCount.equals(ONE))
        {
            v.add(new ASN1Integer(iterationCount));
        }

        return new DERSequence(v);
    }
}
