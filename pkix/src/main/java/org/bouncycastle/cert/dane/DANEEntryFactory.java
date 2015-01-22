package org.bouncycastle.cert.dane;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DigestCalculator;

/**
 * Factory class for creating DANEEntry objects.
 */
public class DANEEntryFactory
{
    private final DANEEntrySelectorFactory selectorFactory;

    /**
     * Base constructor.
     *
     * @param digestCalculator a calculator for the message digest to filter email addresses currently SHA-224.
     */
    public DANEEntryFactory(DigestCalculator digestCalculator)
    {
        this.selectorFactory = new DANEEntrySelectorFactory(digestCalculator);
    }

    /**
     * Return a DANEEntry for the passed in email address and certificate.
     *
     * @param emailAddress the emails address of interest.
     * @param certificate the certificate to be associated with the email address.
     * @throws DANEException in case of issue generating a matching name.
     */
    public DANEEntry createEntry(String emailAddress, X509CertificateHolder certificate)
        throws DANEException
    {
        DANEEntrySelector entrySelector = selectorFactory.createSelector(emailAddress);
        byte[] flags = new byte[3];

        flags[DANEEntry.CERT_USAGE] = 3;
        flags[DANEEntry.SELECTOR] = 0;
        flags[DANEEntry.MATCHING_TYPE] = 0;

        return new DANEEntry(entrySelector.getDomainName(), flags, certificate);
    }
}
