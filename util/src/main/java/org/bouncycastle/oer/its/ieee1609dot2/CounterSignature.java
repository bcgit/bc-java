package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

/**
 * Countersignature ::= Ieee1609Dot2Data (WITH COMPONENTS {...,
 * content (WITH COMPONENTS {...,
 * signedData  (WITH COMPONENTS {...,
 * tbsData (WITH COMPONENTS {...,
 * payload (WITH COMPONENTS {...,
 * data ABSENT,
 * extDataHash PRESENT
 * }),
 * headerInfo(WITH COMPONENTS {...,
 * generationTime PRESENT,
 * expiryTime ABSENT,
 * generationLocation ABSENT,
 * p2pcdLearningRequest ABSENT,
 * missingCrlIdentifier ABSENT,
 * encryptionKey ABSENT
 * })
 * })
 * })
 * })
 * })
 */
public class CounterSignature
    extends Ieee1609Dot2Data
{

    public CounterSignature(UINT8 protocolVersion, Ieee1609Dot2Content content)
    {
        super(protocolVersion, content);
    }

    protected CounterSignature(ASN1Sequence instance)
    {
        super(instance);
    }

    public static Ieee1609Dot2Data getInstance(Object src)
    {
        if (src instanceof Ieee1609Dot2Data)
        {
            return (Ieee1609Dot2Data)src;
        }

        if (src != null)
        {
            return new CounterSignature(ASN1Sequence.getInstance(src));
        }

        return null;
    }


}
