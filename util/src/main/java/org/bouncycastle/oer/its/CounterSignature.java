package org.bouncycastle.oer.its;

import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

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
    extends ASN1Object
{
    private final Uint8 protocolVersion;
    private final SignedData signedData;

    public CounterSignature(Uint8 protocolVersion, SignedData signedData)
    {
        this.protocolVersion = protocolVersion;
        this.signedData = signedData;
    }

    public CounterSignature getInstance(Object src)
    {
        if (src instanceof CounterSignature)
        {
            return (CounterSignature)src;
        }
        Iterator<ASN1Encodable> items = ASN1Sequence.getInstance(src).iterator();
        return new CounterSignature(Uint8.getInstance(items.next()), SignedData.getInstance(items.next()));
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(protocolVersion, signedData);
    }

    public Uint8 getProtocolVersion()
    {
        return protocolVersion;
    }

    public SignedData getSignedData()
    {
        return signedData;
    }
}
