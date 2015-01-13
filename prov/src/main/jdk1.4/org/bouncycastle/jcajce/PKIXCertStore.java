package org.bouncycastle.jcajce;

import java.security.cert.Certificate;
import java.util.Collection;

import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

public interface PKIXCertStore
    extends Store
{
    Collection getMatches(Selector selector)
        throws StoreException;
}
