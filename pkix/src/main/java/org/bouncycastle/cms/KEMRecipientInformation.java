package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KEMRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class KEMRecipientInformation
    extends RecipientInformation
{
    private KEMRecipientInfo info;

    KEMRecipientInformation(
        KEMRecipientInfo        info,
        AlgorithmIdentifier     messageAlgorithm,
        CMSSecureReadable       secureReadable,
        AuthAttributesProvider  additionalData)
    {
        super(info.getKem(), messageAlgorithm, secureReadable, additionalData);

        this.info = info;

        RecipientIdentifier r = info.getRecipientIdentifier();

        if (r.isTagged())
        {
            ASN1OctetString octs = ASN1OctetString.getInstance(r.getId());

            rid = new KeyTransRecipientId(octs.getOctets());   // TODO: should be KEM
        }
        else
        {
            IssuerAndSerialNumber iAnds = IssuerAndSerialNumber.getInstance(r.getId());

            rid = new KeyTransRecipientId(iAnds.getName(), iAnds.getSerialNumber().getValue());    // TODO:
        }
    }

    protected RecipientOperator getRecipientOperator(Recipient recipient)
        throws CMSException
    {
        return ((KEMRecipient)recipient).getRecipientOperator(new AlgorithmIdentifier(keyEncAlg.getAlgorithm(), info), messageAlgorithm, info.getEncryptedKey().getOctets());
    }
}
