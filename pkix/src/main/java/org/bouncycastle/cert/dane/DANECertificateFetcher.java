package org.bouncycastle.cert.dane;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.operator.DigestCalculator;

/**
 * A single shot fetcher for a certificate which will only request the specific DNS record if the
 * DANEEntryFetcher used on construction supports it.
 */
public class DANECertificateFetcher
{
    private final DANEEntryFetcherFactory fetcherFactory;
    private final DANEEntrySelectorFactory selectorFactory;

    /**
     * Base constructor.
     *
     * @param fetcherFactory the fetcher to use for resolving requests.
     * @param digestCalculator the digest calculator to use for calculating sub-domains.
     */
    public DANECertificateFetcher(DANEEntryFetcherFactory fetcherFactory, DigestCalculator digestCalculator)
    {
        this.fetcherFactory = fetcherFactory;
        this.selectorFactory= new DANEEntrySelectorFactory(digestCalculator);
    }

    /**
     * Fetch the certificates associated with the passed in email address if any exists.
     *
     * @param emailAddress the email address of interest.
     * @return a list of X509CertificateHolder objects, or an empty list if none present.
     * @throws DANEException in case of an underlying DNS or record parsing problem.
     */
    public List fetch(String emailAddress)
        throws DANEException
    {
        DANEEntrySelector daneSelector = selectorFactory.createSelector(emailAddress);

        List matches = fetcherFactory.build(daneSelector.getDomainName()).getEntries();
        List certs = new ArrayList(matches.size());

        for (Iterator it = matches.iterator(); it.hasNext();)
        {
            DANEEntry next = (DANEEntry)it.next();
            if (daneSelector.match(next))
            {
                certs.add(next.getCertificate());
            }
        }

        return Collections.unmodifiableList(certs);
    }
}
