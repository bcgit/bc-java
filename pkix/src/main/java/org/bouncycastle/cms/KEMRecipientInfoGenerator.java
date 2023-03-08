package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KEMRecipientInfo;
import org.bouncycastle.asn1.cms.OtherRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;

public abstract class KEMRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    protected final KEMKeyWrapper wrapper;

    private IssuerAndSerialNumber issuerAndSerial;
    private byte[] subjectKeyIdentifier;

    protected KEMRecipientInfoGenerator(IssuerAndSerialNumber issuerAndSerial, KEMKeyWrapper wrapper)
    {
        this.issuerAndSerial = issuerAndSerial;
        this.wrapper = wrapper;
    }

    protected KEMRecipientInfoGenerator(byte[] subjectKeyIdentifier, KEMKeyWrapper wrapper)
    {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
        this.wrapper = wrapper;
    }

    public final RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException
    {
        byte[] encryptedKeyBytes;
        try
        {
            encryptedKeyBytes = wrapper.generateWrappedKey(contentEncryptionKey);
        }
        catch (OperatorException e)
        {
            throw new CMSException("exception wrapping content key: " + e.getMessage(), e);
        }

        RecipientIdentifier recipId;
        if (issuerAndSerial != null)
        {
            recipId = new RecipientIdentifier(issuerAndSerial);
        }
        else
        {
            recipId = new RecipientIdentifier(new DEROctetString(subjectKeyIdentifier));
        }

        return new RecipientInfo(new OtherRecipientInfo(CMSObjectIdentifiers.id_ori_kem,
            new KEMRecipientInfo(recipId, wrapper.getAlgorithmIdentifier(), new DEROctetString(wrapper.getEncapsulation()), wrapper.getKdfAlgorithmIdentifier(), new ASN1Integer(wrapper.getKekLength()), null, wrapper.getWrapAlgorithmIdentifier(),
            new DEROctetString(encryptedKeyBytes))));
    }
}