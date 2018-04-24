package org.bouncycastle.cert.dane;

/**
 * Factories for DANEEntryFetcher objects should implement this.
 * <p>
 * Note: the fetcher should be able to manage both requests of the form
 * <pre>
 *     fetcher.build("test.org");
 * </pre>
 * and
 * <pre>
 *     91d23d115b68072e7a38afeb7e295bd6392a19f25f8328b4ecae4778._smimecert.test.org
 * </pre>
 * In the case of the later ideally just returning a list containing the single entry.
 */
public interface DANEEntryFetcherFactory
{
    /**
     * Build an entry fetcher for the specified domain name.
     *
     * @param domainName the domain name of interest.
     * @return a resolver for fetching entry's associated with domainName.
     */
    DANEEntryFetcher build(String domainName);
}
