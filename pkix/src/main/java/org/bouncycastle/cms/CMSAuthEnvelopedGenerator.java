package org.bouncycastle.cms;

import org.bouncycastle.asn1.cms.OriginatorInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

/**
 * General class for generating a CMS enveloped-data message.
 */
public class CMSAuthEnvelopedGenerator
    extends CMSEnvelopedGenerator
{
    public static final String  AES128_GCM = NISTObjectIdentifiers.id_aes128_GCM.getId();
    public static final String  AES192_GCM = NISTObjectIdentifiers.id_aes192_GCM.getId();
    public static final String  AES256_GCM = NISTObjectIdentifiers.id_aes256_GCM.getId();

    protected CMSAttributeTableGenerator authAttrsGenerator = null;
    protected CMSAttributeTableGenerator unauthAttrsGenerator = null;

    protected OriginatorInfo originatorInfo;

    /**
     * base constructor
     */
    protected CMSAuthEnvelopedGenerator()
    {
    }


    public void setAuthenticatedAttributeGenerator(CMSAttributeTableGenerator protectedAttributeGenerator)
    {
        this.authAttrsGenerator = protectedAttributeGenerator;
    }

    public void setUnauthenticatedAttributeGenerator(CMSAttributeTableGenerator unauthenticatedAttributeGenerator)
    {
        this.unauthAttrsGenerator = unauthenticatedAttributeGenerator;
    }

    public void setOriginatorInfo(OriginatorInformation originatorInfo)
    {
        this.originatorInfo = originatorInfo.toASN1Structure();
    }

    /**
     * Add a generator to produce the recipient info required.
     *
     * @param recipientGenerator a generator of a recipient info object.
     */
    public void addRecipientInfoGenerator(RecipientInfoGenerator recipientGenerator)
    {
        recipientInfoGenerators.add(recipientGenerator);
    }
}
