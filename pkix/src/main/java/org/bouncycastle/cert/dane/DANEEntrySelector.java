package org.bouncycastle.cert.dane;

import org.bouncycastle.util.Selector;

public class DANEEntrySelector
    implements Selector
{
    private final String domainName;

    DANEEntrySelector(String domainName)
    {
        this.domainName = domainName;
    }

    public boolean match(Object obj)
    {
        if (!(obj instanceof DANEEntry))
        {
            return false;
        }

        return ((DANEEntry)obj).getDomainName().equals(domainName);
    }

    public Object clone()
    {
        return this;
    }

    public String getDomainName()
    {
        return domainName;
    }
}
