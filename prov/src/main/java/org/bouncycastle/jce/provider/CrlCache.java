package org.bouncycastle.jce.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.net.URI;
import java.net.URLConnection;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.bouncycastle.jcajce.PKIXCRLStore;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Iterable;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

class CrlCache
{
    private static final int DEFAULT_TIMEOUT = 15000;

    private static Map<URI, WeakReference<PKIXCRLStore>> cache =
        Collections.synchronizedMap(new WeakHashMap<URI, WeakReference<PKIXCRLStore>>());

    static synchronized PKIXCRLStore getCrl(CertificateFactory certFact, Date validDate, URI distributionPoint)
        throws IOException, CRLException
    {
        PKIXCRLStore crlStore = null;

        WeakReference<PKIXCRLStore> markerRef = (WeakReference)cache.get(distributionPoint);
        if (markerRef != null)
        {
            crlStore = (PKIXCRLStore)markerRef.get();
        }

        if (crlStore != null)
        {
            boolean isExpired = false;
            for (Iterator it = crlStore.getMatches(null).iterator(); it.hasNext(); )
            {
                X509CRL crl = (X509CRL)it.next();

                Date nextUpdate = crl.getNextUpdate();
                if (nextUpdate != null && nextUpdate.before(validDate))
                {
                    isExpired = true;
                    break;
                }
            }

            if (!isExpired)
            {
                return crlStore;
            }
        }

        Collection crls;

        if (distributionPoint.getScheme().equals("ldap"))
        {
            crls = getCrlsFromLDAP(certFact, distributionPoint);
        }
        else
        {
            // http, https, ftp
            crls = getCrls(certFact, distributionPoint);
        }

        LocalCRLStore localCRLStore = new LocalCRLStore(new CollectionStore<CRL>(crls));

        cache.put(distributionPoint, new WeakReference<PKIXCRLStore>(localCRLStore));

        return localCRLStore;
    }

    private static Collection getCrlsFromLDAP(CertificateFactory certFact, URI distributionPoint)
        throws IOException, CRLException
    {
        Map<String, String> env = new Hashtable<String, String>();

        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, distributionPoint.toString());

        byte[] val = null;
        try
        {
            DirContext ctx = new InitialDirContext((Hashtable)env);
            Attributes avals = ctx.getAttributes("");
            Attribute aval = avals.get("certificateRevocationList;binary");
            val = (byte[])aval.get();
        }
        catch (NamingException e)
        {
            throw new CRLException("issue connecting to: " + distributionPoint.toString(), e);
        }

        if ((val == null) || (val.length == 0))
        {
            throw new CRLException("no CRL returned from: " + distributionPoint);
        }
        else
        {
            return certFact.generateCRLs(new ByteArrayInputStream(val));
        }
    }

    private static Collection getCrls(CertificateFactory certFact, URI distributionPoint)
        throws IOException, CRLException
    {
        URLConnection urlConnection = distributionPoint.toURL().openConnection();

        urlConnection.setConnectTimeout(DEFAULT_TIMEOUT);
        urlConnection.setReadTimeout(DEFAULT_TIMEOUT);

        InputStream crlIn = urlConnection.getInputStream();

        Collection crls = certFact.generateCRLs(crlIn);

        crlIn.close();

        return crls;
    }

    private static class LocalCRLStore<T extends CRL>
        implements PKIXCRLStore, Iterable<CRL>
    {
        private Collection<CRL> _local;

        /**
         * Basic constructor.
         *
         * @param collection - initial contents for the store, this is copied.
         */
        public LocalCRLStore(
            Store<CRL> collection)
        {
            _local = new ArrayList<CRL>(collection.getMatches(null));
        }

        /**
         * Return the matches in the collection for the passed in selector.
         *
         * @param selector the selector to match against.
         * @return a possibly empty collection of matching objects.
         */
        public Collection getMatches(Selector selector)
        {
            if (selector == null)
            {
                return new ArrayList<CRL>(_local);
            }
            else
            {
                List<CRL> col = new ArrayList<CRL>();

                for (CRL obj : _local)
                {
                    if (selector.match(obj))
                    {
                        col.add(obj);
                    }
                }

                return col;
            }
        }

        public Iterator<CRL> iterator()
        {
            return getMatches(null).iterator();
        }
    }
}
