package org.bouncycastle.jcajce;

import java.security.cert.Certificate;
import java.util.Collection;

import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

/**
 * Generic interface for a PKIX based certificate store.
 *
 * @param <T> the certificate type.
 */
public interface PKIXCertStore<T extends Certificate>
    extends Store<T>
{
    /**
     * Return the matches associated with the passed in selector.
     *
     * @param selector the selector defining the match criteria.
     * @return a collection of matches with the selector, an empty selector if there are none.
     * @throws StoreException in the event of an issue doing a match.
     */
    Collection<T> getMatches(Selector<T> selector)
        throws StoreException;
}
