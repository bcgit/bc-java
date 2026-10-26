package org.bouncycastle.cms;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Iterable;

public class RecipientInformationStore
    implements Iterable<RecipientInformation>
{
    private final List all; //ArrayList[RecipientInformation]

    /**
     * Create a store containing a single RecipientInformation object.
     *
     * @param recipientInformation the signer information to contain.
     */
    public RecipientInformationStore(
        RecipientInformation  recipientInformation)
    {
        this.all = new ArrayList(1);
        this.all.add(recipientInformation);
    }

    public RecipientInformationStore(
        Collection<RecipientInformation> recipientInfos)
    {
        this.all = new ArrayList(recipientInfos);
    }

    /**
     * Return the first RecipientInformation object that matches the
     * passed in selector. Null if there are no matches.
     *
     * @param selector to identify a recipient
     * @return a single RecipientInformation object. Null if none matches.
     */
    public RecipientInformation get(
        RecipientId selector)
    {
        Collection list = getRecipients(selector);

        return list.size() == 0 ? null : (RecipientInformation)list.iterator().next();
    }

    /**
     * Return the number of recipients in the collection.
     *
     * @return number of recipients identified.
     */
    public int size()
    {
        return all.size();
    }

    /**
     * Return all recipients in the collection
     *
     * @return a collection of recipients.
     */
    public Collection<RecipientInformation> getRecipients()
    {
        return new ArrayList(all);
    }

    /**
     * Return possible empty collection with recipients matching the passed in RecipientId
     *
     * @param selector a recipient id to select against.
     * @return a collection of RecipientInformation objects.
     */
    public Collection<RecipientInformation> getRecipients(
        RecipientId selector)
    {
        if (selector instanceof PKIXRecipientId)
        {
            PKIXRecipientId pkixId = (PKIXRecipientId)selector;

            X500Name issuer = pkixId.getIssuer();
            byte[] subjectKeyId = pkixId.getSubjectKeyIdentifier();

            if (issuer != null && subjectKeyId != null)
            {
                List<RecipientInformation> results = new ArrayList();

                results.addAll(findRecipients(new PKIXRecipientId(pkixId.getType(), issuer, pkixId.getSerialNumber(), null)));
                results.addAll(findRecipients(new PKIXRecipientId(pkixId.getType(), null, null, subjectKeyId)));

                return results;
            }
        }

        return findRecipients(selector);
    }

    private List findRecipients(RecipientId selector)
    {
        // a message carries a handful of recipients: a scan costs no more than a hash lookup
        // and, unlike a map keyed on the recipient ids, cannot be flooded by ids chosen to collide
        List results = new ArrayList();

        for (Iterator it = all.iterator(); it.hasNext();)
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            if (selector.equals(recipient.getRID()))
            {
                results.add(recipient);
            }
        }

        return results;
    }


    /**
     * Support method for Iterable where available.
     */
    public Iterator<RecipientInformation> iterator()
    {
        return getRecipients().iterator();
    }
}
