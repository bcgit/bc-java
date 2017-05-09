package org.bouncycastle.asn1.cmc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * Other info implements the choice component of CMCStatusInfoV2.
 * <p>
 * OtherStatusInfo ::= CHOICE {
 * failInfo              CMCFailInfo,
 * pendInfo              PendInfo,
 * extendedFailInfo      ExtendedFailInfo
 * }
 */
public class OtherStatusInfo
    extends ASN1Object
    implements ASN1Choice
{
    private final CMCFailInfo failInfo;
    private final PendInfo pendInfo;
    private final ExtendedFailInfo extendedFailInfo;

    public static OtherStatusInfo getInstance(Object obj)
    {
        if (obj instanceof OtherStatusInfo)
        {
            return (OtherStatusInfo)obj;
        }

        if (obj instanceof ASN1Encodable)
        {
            ASN1Encodable asn1Value = ((ASN1Encodable)obj).toASN1Primitive();

            if (asn1Value instanceof ASN1Integer) // CMCFail info is an asn1 integer.
            {
                return new OtherStatusInfo(CMCFailInfo.getInstance(asn1Value));
            }
            else if (asn1Value instanceof ASN1Sequence) // PendInfo is a sequence.
            {
                if (((ASN1Sequence)asn1Value).getObjectAt(0) instanceof ASN1ObjectIdentifier)
                {
                    return new OtherStatusInfo(ExtendedFailInfo.getInstance(asn1Value));
                }
                return new OtherStatusInfo(PendInfo.getInstance(asn1Value));
            }
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("parsing error: " + e.getMessage());
            }
        }                          
        throw new IllegalArgumentException("unknown object in getInstance(): " + obj.getClass().getName());
    }

    OtherStatusInfo(CMCFailInfo failInfo)
    {
        this(failInfo, null, null);
    }

    OtherStatusInfo(PendInfo pendInfo)
    {
        this(null, pendInfo, null);
    }

    OtherStatusInfo(ExtendedFailInfo extendedFailInfo)
    {
        this(null, null, extendedFailInfo);
    }

    private OtherStatusInfo(CMCFailInfo failInfo, PendInfo pendInfo, ExtendedFailInfo extendedFailInfo)
    {
        this.failInfo = failInfo;
        this.pendInfo = pendInfo;
        this.extendedFailInfo = extendedFailInfo;
    }

    public boolean isPendingInfo()
    {
        return pendInfo != null;
    }

    public boolean isFailInfo()
    {
        return failInfo != null;
    }


    public boolean isExtendedFailInfo()
    {
        return extendedFailInfo != null;
    }


    public ASN1Primitive toASN1Primitive()
    {
        if (pendInfo != null)
        {
            return pendInfo.toASN1Primitive();
        }
        else if (failInfo != null)
        {
            return failInfo.toASN1Primitive();
        }
        return extendedFailInfo.toASN1Primitive();
    }
}
