package org.bouncycastle.asn1.pkcs;

import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

public class PBKDF2Params
    extends ASN1Object
{
    private ASN1OctetString octStr;
    private ASN1Integer      iterationCount;
    private ASN1Integer      keyLength;

    public static PBKDF2Params getInstance(
        Object  obj)
    {
        if (obj instanceof PBKDF2Params)
        {
            return (PBKDF2Params)obj;
        }

        if (obj != null)
        {
            return new PBKDF2Params(ASN1Sequence.getInstance(obj));
        }

        return null;
    }
    
    public PBKDF2Params(
        byte[]  salt,
        int     iterationCount)
    {
        this.octStr = new DEROctetString(salt);
        this.iterationCount = new ASN1Integer(iterationCount);
    }

    public PBKDF2Params(
        byte[]  salt,
        int     iterationCount,
        int     keyLength)
    {
        this(salt, iterationCount);

        this.keyLength = new ASN1Integer(keyLength);
    }

    private PBKDF2Params(
        ASN1Sequence  seq)
    {
        Enumeration e = seq.getObjects();

        octStr = (ASN1OctetString)e.nextElement();
        iterationCount = (ASN1Integer)e.nextElement();

        if (e.hasMoreElements())
        {
            keyLength = (ASN1Integer)e.nextElement();
        }
        else
        {
            keyLength = null;
        }
    }

    public byte[] getSalt()
    {
        return octStr.getOctets();
    }

    public BigInteger getIterationCount()
    {
        return iterationCount.getValue();
    }

    public BigInteger getKeyLength()
    {
        if (keyLength != null)
        {
            return keyLength.getValue();
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(octStr);
        v.add(iterationCount);

        if (keyLength != null)
        {
            v.add(keyLength);
        }

        return new DERSequence(v);
    }
}
