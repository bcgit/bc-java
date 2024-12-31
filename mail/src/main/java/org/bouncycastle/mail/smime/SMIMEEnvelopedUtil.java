package org.bouncycastle.mail.smime;

import java.util.HashSet;
import java.util.Set;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformationStore;

public class SMIMEEnvelopedUtil
{
    private static Set<ASN1ObjectIdentifier> authOIDs = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        authOIDs.add(NISTObjectIdentifiers.id_aes128_GCM);
        authOIDs.add(NISTObjectIdentifiers.id_aes128_GCM);
        authOIDs.add(NISTObjectIdentifiers.id_aes128_GCM);
    }

    /**
     * Parse the passed in MimeMessage extracting the RecipientInfos from it.
     *
     * @param message the message to be parsed.
     * @return the RecipientInformation store for the passed in message.
     * @throws MessagingException
     * @throws CMSException
     */
    public static RecipientInformationStore getRecipientInfos(MimeBodyPart message) throws MessagingException, CMSException
    {
        if(message.getContentType().equals(SMIMEAuthEnvelopedGenerator.AUTH_ENVELOPED_DATA_CONTENT_TYPE))
        {
            return new SMIMEAuthEnveloped(message).getRecipientInfos();
        }
        return new SMIMEEnveloped(message).getRecipientInfos();
    }

    /**
     * Utility method which will return an SMIMEEnvelopedGenerator or an
     * SMIMEAuthEnvelopedGenerator as appropriate for the algorithm OID passed in.
     *
     * @param algorithm algorithm OID
     * @return a SMIME Enveloped Generator class.
     */
    public static SMIMEEnvelopedGenerator createGenerator(ASN1ObjectIdentifier algorithm)
    {
        if (authOIDs.contains(algorithm))
        {
            return new SMIMEAuthEnvelopedGenerator();
        }
        return new SMIMEEnvelopedGenerator();
    }
}
