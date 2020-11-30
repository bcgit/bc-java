package org.bouncycastle.x509;

import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.PKIXParameters;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.util.StoreException;

abstract class PKIXCRLUtil
{
    static Set findCRLs(X509CRLStoreSelector crlselect, PKIXParameters paramsPKIX)
        throws AnnotatedException
    {
        HashSet completeSet = new HashSet();

        // get complete CRL(s)
        try
        {
            findCRLs(completeSet, crlselect, paramsPKIX.getCertStores());
        }
        catch (AnnotatedException e)
        {
            throw new AnnotatedException("Exception obtaining complete CRLs.", e);
        }

        return completeSet;
    }

    /**
     * Add to a HashSet any and all CRLs found in the X509Store's that are matching the crlSelect
     * criteria.
     *
     * @param crls
     *            the {@link HashSet} to add the CRLs to.
     * @param crlSelect
     *            a {@link X509CRLStoreSelector} object that will be used to select the CRLs
     * @param crlStores
     *            a List containing only {@link org.bouncycastle.x509.X509Store X509Store} objects.
     *            These are used to search for CRLs
     */
    private static void findCRLs(HashSet crls, X509CRLStoreSelector crlSelect, List crlStores) throws AnnotatedException
    {
        AnnotatedException lastException = null;
        boolean foundValidStore = false;

        Iterator iter = crlStores.iterator();
        while (iter.hasNext())
        {
            Object obj = iter.next();
            if (obj instanceof X509Store)
            {
                X509Store store = (X509Store)obj;
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
                    crls.addAll(store.getCRLs(crlSelect));
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
