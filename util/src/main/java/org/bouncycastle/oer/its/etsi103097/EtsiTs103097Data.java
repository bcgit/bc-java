package org.bouncycastle.oer.its.etsi103097;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Data;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

/**
 * EtsiTs103097Data::=Ieee1609Dot2Data (WITH COMPONENTS {...,
 * content (WITH COMPONENTS {...,
 * signedData (WITH COMPONENTS {..., -- constraints on signed data headers
 * tbsData (WITH COMPONENTS {
 * headerInfo (WITH COMPONENTS {...,
 * generationTime PRESENT,
 * p2pcdLearningRequest ABSENT,
 * missingCrlIdentifier ABSENT
 * })
 * }),
 * signer (WITH COMPONENTS {...,  --constraints on the certificate
 * certificate ((WITH COMPONENT (EtsiTs103097Certificate))^(SIZE(1)))
 * })
 * }),
 * encryptedData (WITH COMPONENTS {..., -- constraints on encrypted data headers
 * recipients  (WITH COMPONENT (
 * (WITH COMPONENTS {...,
 * pskRecipInfo ABSENT,
 * symmRecipInfo ABSENT,
 * rekRecipInfo ABSENT
 * })
 * ))
 * }),
 * signedCertificateRequest ABSENT
 * })
 * })
 */
public class EtsiTs103097Data
    extends Ieee1609Dot2Data
{

    public EtsiTs103097Data(Ieee1609Dot2Content content)
    {
        super(new UINT8(3), content);
    }

    public EtsiTs103097Data(UINT8 protocolVersion, Ieee1609Dot2Content content)
    {
        super(protocolVersion, content);
    }

    protected EtsiTs103097Data(ASN1Sequence src)
    {
        super(src);
    }

    public static EtsiTs103097Data getInstance(Object o)
    {
        if (o instanceof EtsiTs103097Data)
        {
            return (EtsiTs103097Data)o;
        }
        if (o != null)
        {
            return new EtsiTs103097Data(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
