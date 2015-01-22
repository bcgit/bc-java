package org.bouncycastle.cms;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.Iterable;

public class SignerInformationStore
    implements Iterable<SignerInformation>
{
    private List all = new ArrayList();
    private Map table = new HashMap();

    /**
     * Create a store containing a single SignerInformation object.
     *
     * @param signerInfo the signer information to contain.
     */
    public SignerInformationStore(
        SignerInformation  signerInfo)
    {
        this.all = new ArrayList(1);
        this.all.add(signerInfo);

        SignerId sid = signerInfo.getSID();

        table.put(sid, all);
    }

    /**
     * Create a store containing a collection of SignerInformation objects.
     *
     * @param signerInfos a collection signer information objects to contain.
     */
    public SignerInformationStore(
        Collection<SignerInformation>  signerInfos)
    {
        Iterator    it = signerInfos.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            SignerId            sid = signer.getSID();

            List list = (ArrayList)table.get(sid);
            if (list == null)
            {
                list = new ArrayList(1);
                table.put(sid, list);
            }

            list.add(signer);
        }

        this.all = new ArrayList(signerInfos);
    }

    /**
     * Return the first SignerInformation object that matches the
     * passed in selector. Null if there are no matches.
     * 
     * @param selector to identify a signer
     * @return a single SignerInformation object. Null if none matches.
     */
    public SignerInformation get(
        SignerId        selector)
    {
        Collection list = getSigners(selector);

        return list.size() == 0 ? null : (SignerInformation) list.iterator().next();
    }

    /**
     * Return the number of signers in the collection.
     * 
     * @return number of signers identified.
     */
    public int size()
    {
        return all.size();
    }

    /**
     * Return all signers in the collection
     * 
     * @return a collection of signers.
     */
    public Collection<SignerInformation> getSigners()
    {
        return new ArrayList(all);
    }

    /**
     * Return possible empty collection with signers matching the passed in SignerId
     * 
     * @param selector a signer id to select against.
     * @return a collection of SignerInformation objects.
     */
    public Collection<SignerInformation> getSigners(
        SignerId selector)
    {
        if (selector.getIssuer() != null && selector.getSubjectKeyIdentifier() != null)
        {
            List results = new ArrayList();

            Collection match1 = getSigners(new SignerId(selector.getIssuer(), selector.getSerialNumber()));

            if (match1 != null)
            {
                results.addAll(match1);
            }

            Collection match2 = getSigners(new SignerId(selector.getSubjectKeyIdentifier()));

            if (match2 != null)
            {
                results.addAll(match2);
            }

            return results;
        }
        else
        {
            List list = (ArrayList)table.get(selector);

            return list == null ? new ArrayList() : new ArrayList(list);
        }
    }

    /**
     * Support method for Iterable where available.
     */
    public Iterator<SignerInformation> iterator()
    {
        return getSigners().iterator();
    }
}
