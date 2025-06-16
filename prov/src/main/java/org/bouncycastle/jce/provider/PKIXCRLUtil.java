package org.bouncycastle.jce.provider;

import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jcajce.PKIXCRLStoreSelector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

abstract class PKIXCRLUtil
{
    static Set findCRLs(PKIXCRLStoreSelector crlselect, Date validityDate, List certStores, List pkixCrlStores)
        throws AnnotatedException
    {
        Set initialSet = new HashSet();

        // get complete CRL(s)
        try
        {
            findCRLs(initialSet, crlselect, pkixCrlStores);
            findCRLs(initialSet, crlselect, certStores);
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
            
            Date nextUpdate = crl.getNextUpdate();
            if (nextUpdate == null || nextUpdate.after(validityDate))
            {
                X509Certificate cert = crlselect.getCertificateChecking();

                if (null == cert || crl.getThisUpdate().before(cert.getNotAfter()))
                {
                    finalSet.add(crl);
                }
            }
        }

        return finalSet;
    }

    /**
     * Add to a Set any and all CRLs found in the X509Store's that are matching the crlSelect
     * critera.
     *
     * @param crls
     *            the {@link Set} to add the CRLs to.
     * @param crlSelect
     *            a {@link org.bouncycastle.jcajce.PKIXCRLStoreSelector} object that will be used to
     *            select the CRLs
     * @param crlStores
     *            a List containing only {@link Store} objects. These are used to search for CRLs
     */
    private static void findCRLs(Set crls, PKIXCRLStoreSelector crlSelect, List crlStores) throws AnnotatedException
    {
        AnnotatedException lastException = null;
        boolean foundValidStore = false;

        for (Object obj : crlStores)
        {
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
                    lastException = new AnnotatedException("Exception searching in X.509 CRL store.", e);
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
                    lastException = new AnnotatedException("Exception searching in X.509 CRL store.", e);
                }
            }
        }

        if (!foundValidStore && lastException != null)
        {
            throw lastException;
        }
    }
}
