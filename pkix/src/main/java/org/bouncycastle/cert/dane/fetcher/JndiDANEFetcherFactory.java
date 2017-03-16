package org.bouncycastle.cert.dane.fetcher;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;

import javax.naming.Binding;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.bouncycastle.cert.dane.DANEEntry;
import org.bouncycastle.cert.dane.DANEEntryFetcher;
import org.bouncycastle.cert.dane.DANEEntryFetcherFactory;
import org.bouncycastle.cert.dane.DANEException;

/**
 * A DANE entry fetcher implemented using JNDI.
 */
public class JndiDANEFetcherFactory
    implements DANEEntryFetcherFactory
{
    private static final String DANE_TYPE = "53";

    private List dnsServerList = new ArrayList();
    private boolean isAuthoritative;

    /**
     * Specify the dnsServer to use.
     *
     * @param dnsServer IP address/name of the dns server
     * @return the current factory.
     */
    public JndiDANEFetcherFactory usingDNSServer(String dnsServer)
    {
        this.dnsServerList.add(dnsServer);

        return this;
    }

    /**
     * Specify requests must be authoritative, or not (default false).
     *
     * @param isAuthoritative true if requests must be authoritative, false otherwise.
     * @return the current factory..
     */
    public JndiDANEFetcherFactory setAuthoritative(boolean isAuthoritative)
    {
        this.isAuthoritative = isAuthoritative;

        return this;
    }

    /**
     * Build an entry fetcher for the specified domain name.
     *
     * @param domainName the domain name of interest.
     * @return a resolver for fetching entry's associated with domainName.
     */
    public DANEEntryFetcher build(final String domainName)
    {
        final Hashtable env = new Hashtable();

        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        env.put(Context.AUTHORITATIVE, isAuthoritative ? "true" : "false"); // JDK compatibility

        if (dnsServerList.size() > 0)
        {
            StringBuffer dnsServers = new StringBuffer();

            for (Iterator it = dnsServerList.iterator(); it.hasNext(); )
            {
                if (dnsServers.length() > 0)
                {
                    dnsServers.append(" ");
                }
                dnsServers.append("dns://" + it.next());
            }

            env.put(Context.PROVIDER_URL, dnsServers.toString());
        }

        return new DANEEntryFetcher()
        {
            public List getEntries()
                throws DANEException
            {
                List entries = new ArrayList();

                try
                {
                    DirContext ctx = new InitialDirContext(env);

                    NamingEnumeration bindings;
                    if (domainName.indexOf("_smimecert.") > 0)
                    {
                        // need to use fully qualified domain name if using named DNS server.
                        Attributes attrs = ctx.getAttributes(domainName, new String[]{DANE_TYPE});
                        Attribute smimeAttr = attrs.get(DANE_TYPE);

                        if (smimeAttr != null)
                        {
                            addEntries(entries, domainName, smimeAttr);
                        }
                    }
                    else
                    {
                        bindings = ctx.listBindings("_smimecert." + domainName);

                        while (bindings.hasMore())
                        {
                            Binding b = (Binding)bindings.next();

                            DirContext sc = (DirContext)b.getObject();

                            String name = sc.getNameInNamespace().substring(1, sc.getNameInNamespace().length() - 1);

                            // need to use fully qualified domain name if using named DNS server.
                            Attributes attrs = ctx.getAttributes(name, new String[]{DANE_TYPE});
                            Attribute smimeAttr = attrs.get(DANE_TYPE);

                            if (smimeAttr != null)
                            {
                                String fullName = sc.getNameInNamespace();
                                String domainName = fullName.substring(1, fullName.length() - 1);

                                addEntries(entries, domainName, smimeAttr);
                            }
                        }
                    }

                    return entries;
                }
                catch (NamingException e)
                {
                    throw new DANEException("Exception dealing with DNS: " + e.getMessage(), e);
                }
            }
        };
    }

    private void addEntries(List entries, String domainName, Attribute smimeAttr)
        throws NamingException, DANEException
    {
        for (int index = 0; index != smimeAttr.size(); index++)
        {
            byte[] data = (byte[])smimeAttr.get(index);

            if (DANEEntry.isValidCertificate(data))
            {
                try
                {
                    entries.add(new DANEEntry(domainName, data));
                }
                catch (IOException e)
                {
                    throw new DANEException("Exception parsing entry: " + e.getMessage(), e);
                }
            }
        }
    }
}
