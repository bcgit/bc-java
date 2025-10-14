package org.bouncycastle.cert.cmp;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmp.Challenge;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.POPODecKeyChallContent;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * POPODecKeyChallContent ::= SEQUENCE OF Challenge
 * -- One Challenge per encryption key certification request (in the
 * -- same order as these requests appear in CertReqMessages).
 */
public class POPODecryptionKeyChallengeContent
{
    private final ASN1Sequence content;
    private final DigestCalculatorProvider owfCalcProvider;

    POPODecryptionKeyChallengeContent(POPODecKeyChallContent challenges, DigestCalculatorProvider owfCalcProvider)
    {
        this.content = ASN1Sequence.getInstance(challenges.toASN1Primitive());
        this.owfCalcProvider = owfCalcProvider;
    }

    public ChallengeContent[] toChallengeArray()
        throws CMPException
    {
        ChallengeContent[] result = new ChallengeContent[content.size()];
        DigestCalculator owfCalc = null;

        for (int i = 0; i != result.length; i++)
        {
            Challenge c = Challenge.getInstance(content.getObjectAt(i));
            if (c.getOwf() != null)
            {
                try
                {
                    owfCalc = owfCalcProvider.get(c.getOwf());
                }
                catch (OperatorCreationException e)
                {
                    throw new CMPException(e.getMessage(), e);
                }
            }
            result[i] = new ChallengeContent(Challenge.getInstance(content.getObjectAt(i)), owfCalc);
        }

        return result;
    }

    public static POPODecryptionKeyChallengeContent fromPKIBody(PKIBody pkiBody, DigestCalculatorProvider owfProvider)
    {
        if (pkiBody.getType() != PKIBody.TYPE_POPO_CHALL)
        {
            throw new IllegalArgumentException("content of PKIBody wrong type: " + pkiBody.getType());
        }

        return new POPODecryptionKeyChallengeContent(POPODecKeyChallContent.getInstance(pkiBody.getContent()), owfProvider);
    }

    public POPODecKeyChallContent toASN1Structure()
    {
        return POPODecKeyChallContent.getInstance(content);
    }
}
