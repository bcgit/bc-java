package org.bouncycastle.jce.provider;

import org.bouncycastle.jce.cert.CertStore;
import org.bouncycastle.jce.cert.CertStoreException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jcajce.PKIXCRLStore;
import org.bouncycastle.jcajce.PKIXCRLStoreSelector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

class PKIXCRLUtil
{
    public Set findCRLs(PKIXCRLStoreSelector crlselect, Date validityDate, List certStores, List pkixCrlStores)
        throws AnnotatedException
    {
        Set initialSet = new HashSet();

        // get complete CRL(s)
        try
        {
            initialSet.addAll(findCRLs(crlselect, pkixCrlStores));
            initialSet.addAll(findCRLs(crlselect, certStores));
        }
        catch (AnnotatedException e)
        {
            throw new AnnotatedException("Exception obtaining complete CRLs.", e);
        }

        Set finalSet = new HashSet();

        // based on RFC 5280 6.3.3
        for (Iterator it = initialSet.iterator(); it.hasNext();)
        {
            X509CRL crl = (X509CRL)it.next();

            if (crl.getNextUpdate().after(validityDate))
            {
                X509Certificate cert = crlselect.getCertificateChecking();

                if (cert != null)
                {
                    if (crl.getThisUpdate().before(cert.getNotAfter()))
                    {
                        finalSet.add(crl);
                    }
                }
                else
                {
                    finalSet.add(crl);
                }
            }
        }

        return finalSet;
    }

    /**
     * Return a Collection of all CRLs found in the X509Store's that are
     * matching the crlSelect criteriums.
     *
     * @param crlSelect a {@link org.bouncycastle.jcajce.PKIXCRLStoreSelector} object that will be used
     *            to select the CRLs
     * @param crlStores a List containing only
     *            {@link Store} objects.
     *            These are used to search for CRLs
     *
     * @return a Collection of all found {@link java.security.cert.X509CRL X509CRL} objects. May be
     *         empty but never <code>null</code>.
     */
    private final Collection findCRLs(PKIXCRLStoreSelector crlSelect,
        List crlStores) throws AnnotatedException
    {
        Set crls = new HashSet();
        Iterator iter = crlStores.iterator();

        AnnotatedException lastException = null;
        boolean foundValidStore = false;

        while (iter.hasNext())
        {
            Object obj = iter.next();

            if (obj instanceof Store)
            {
                Store store = (Store)obj;

                try
                {
                    crls.addAll(store.getMatches(crlSelect));
                    foundValidStore = true;
                }
                catch (StoreException e)
                {
                    lastException = new AnnotatedException(
                        "Exception searching in X.509 CRL store.", e);
                }
            }
            else
            {
                CertStore store = (CertStore)obj;

                try
                {
                    crls.addAll(PKIXCRLStoreSelector.getCRLs(crlSelect, store));
                    foundValidStore = true;
                }
                catch (CertStoreException e)
                {
                    lastException = new AnnotatedException(
                        "Exception searching in X.509 CRL store.", e);
                }
            }
        }
        if (!foundValidStore && lastException != null)
        {
            throw lastException;
        }
        return crls;
    }

}
