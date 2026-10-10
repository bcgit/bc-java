package org.bouncycastle.cert.dane.fetcher;

import junit.framework.TestCase;

/**
 * Same-package test for the package-private name handling in JndiDANEFetcherFactory.
 */
public class JndiDANEFetcherFactoryTest
    extends TestCase
{
    public void testToDomainName()
    {
        // the JNDI DNS provider reports a listed entry's full name in presentation form with a root label
        // (e.g. "<hash>._smimecert.test.org."); only that trailing dot is to be removed.
        assertEquals("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15._smimecert.test.org",
            JndiDANEFetcherFactory.toDomainName("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15._smimecert.test.org."));
        assertEquals("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15._smimecert.test.org",
            JndiDANEFetcherFactory.toDomainName("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15._smimecert.test.org"));
        assertEquals(".", JndiDANEFetcherFactory.toDomainName("."));
        assertEquals("", JndiDANEFetcherFactory.toDomainName(""));
    }
}
