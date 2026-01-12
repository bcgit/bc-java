package org.bouncycastle.asn1.cmc;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 * CMCFailInfo ::= INTEGER {
 *     badAlg          (0),
 *     badMessageCheck (1),
 *     badRequest      (2),
 *     badTime         (3),
 *     badCertId       (4),
 *     unsupportedExt  (5),
 *     mustArchiveKeys (6),
 *     badIdentity     (7),
 *     popRequired     (8),
 *     popFailed       (9),
 *     noKeyReuse      (10),
 *     internalCAError (11),
 *     tryLater        (12),
 *     authDataFail    (13)
 * }
 * </pre>
 */
public class CMCFailInfo
    extends ASN1Object
{
    public static final CMCFailInfo badAlg = new CMCFailInfo(ASN1Integer.valueOf(0));
    public static final CMCFailInfo badMessageCheck = new CMCFailInfo(ASN1Integer.valueOf(1));
    public static final CMCFailInfo badRequest = new CMCFailInfo(ASN1Integer.valueOf(2));
    public static final CMCFailInfo badTime = new CMCFailInfo(ASN1Integer.valueOf(3));
    public static final CMCFailInfo badCertId = new CMCFailInfo(ASN1Integer.valueOf(4));
    public static final CMCFailInfo unsupportedExt = new CMCFailInfo(ASN1Integer.valueOf(5));
    public static final CMCFailInfo mustArchiveKeys = new CMCFailInfo(ASN1Integer.valueOf(6));
    public static final CMCFailInfo badIdentity = new CMCFailInfo(ASN1Integer.valueOf(7));
    public static final CMCFailInfo popRequired = new CMCFailInfo(ASN1Integer.valueOf(8));
    public static final CMCFailInfo popFailed = new CMCFailInfo(ASN1Integer.valueOf(9));
    public static final CMCFailInfo noKeyReuse = new CMCFailInfo(ASN1Integer.valueOf(10));
    public static final CMCFailInfo internalCAError = new CMCFailInfo(ASN1Integer.valueOf(11));
    public static final CMCFailInfo tryLater = new CMCFailInfo(ASN1Integer.valueOf(12));
    public static final CMCFailInfo authDataFail = new CMCFailInfo(ASN1Integer.valueOf(13));

    private static Map range = new HashMap();

    static
    {
        range.put(badAlg.value, badAlg);
        range.put(badMessageCheck.value, badMessageCheck);
        range.put(badRequest.value, badRequest);
        range.put(badTime.value, badTime);
        range.put(badCertId.value, badCertId);
        range.put(popRequired.value, popRequired);
        range.put(unsupportedExt.value, unsupportedExt);
        range.put(mustArchiveKeys.value, mustArchiveKeys);
        range.put(badIdentity.value, badIdentity);
        range.put(popRequired.value, popRequired);
        range.put(popFailed.value, popFailed);
        range.put(badCertId.value, badCertId);
        range.put(popRequired.value, popRequired);
        range.put(noKeyReuse.value, noKeyReuse);
        range.put(internalCAError.value, internalCAError);
        range.put(tryLater.value, tryLater);
        range.put(authDataFail.value, authDataFail);
    }

    private final ASN1Integer value;

    private CMCFailInfo(ASN1Integer value)
    {
         this.value = value;
    }

    public static CMCFailInfo getInstance(Object o)
    {
        if (o instanceof CMCFailInfo)
        {
            return (CMCFailInfo)o;
        }

        if (o != null)
        {
            CMCFailInfo status = (CMCFailInfo)range.get(ASN1Integer.getInstance(o));

            if (status != null)
            {
                return status;
            }

            throw new IllegalArgumentException("unknown object in getInstance(): " + o.getClass().getName());
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return value;
    }
}
