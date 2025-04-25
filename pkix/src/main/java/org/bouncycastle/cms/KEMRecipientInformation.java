package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KEMRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

public class KEMRecipientInformation
    extends RecipientInformation
{
    private KEMRecipientInfo info;

    KEMRecipientInformation(
        KEMRecipientInfo        info,
        AlgorithmIdentifier     messageAlgorithm,
        CMSSecureReadable       secureReadable)
    {
        super(info.getKem(), messageAlgorithm, secureReadable);

        this.info = info;

        RecipientIdentifier r = info.getRecipientIdentifier();

        if (r.isTagged())
        {
            ASN1OctetString octs = ASN1OctetString.getInstance(r.getId());

            rid = new KEMRecipientId(octs.getOctets());
        }
        else
        {
            IssuerAndSerialNumber iAnds = IssuerAndSerialNumber.getInstance(r.getId());

            rid = new KEMRecipientId(iAnds.getName(), iAnds.getSerialNumber().getValue());
        }
    }

    public AlgorithmIdentifier getKdfAlgorithm()
    {
        return info.getKdf();
    }

    public byte[] getUkm()
    {
        return Arrays.clone(info.getUkm());
    }

    public byte[] getEncapsulation()
    {
        return Arrays.clone(info.getKemct().getOctets());
    }

    protected RecipientOperator getRecipientOperator(Recipient recipient)
        throws CMSException
    {
        return ((KEMRecipient)recipient).getRecipientOperator(new AlgorithmIdentifier(keyEncAlg.getAlgorithm(), info), messageAlgorithm, info.getEncryptedKey().getOctets());
    }
}
