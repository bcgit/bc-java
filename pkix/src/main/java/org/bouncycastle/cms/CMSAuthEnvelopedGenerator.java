package org.bouncycastle.cms;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.OriginatorInfo;

/**
 * General class for generating a CMS enveloped-data message.
 */
public class CMSAuthEnvelopedGenerator
    extends CMSEnvelopedGenerator
{
    static Set<ASN1ObjectIdentifier> cipherNeedsMacAppended = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        cipherNeedsMacAppended.add(CMSAlgorithm.AES128_GCM);
        cipherNeedsMacAppended.add(CMSAlgorithm.AES192_GCM);
        cipherNeedsMacAppended.add(CMSAlgorithm.AES256_GCM);
        cipherNeedsMacAppended.add(CMSAlgorithm.AES128_CCM);
        cipherNeedsMacAppended.add(CMSAlgorithm.AES192_CCM);
        cipherNeedsMacAppended.add(CMSAlgorithm.AES256_CCM);
    }

    final List recipientInfoGenerators = new ArrayList();

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
