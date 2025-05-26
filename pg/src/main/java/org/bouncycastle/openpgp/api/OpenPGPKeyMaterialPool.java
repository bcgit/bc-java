package org.bouncycastle.openpgp.api;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.bouncycastle.bcpg.KeyIdentifier;

/**
 * Implementation of the {@link OpenPGPKeyMaterialProvider} which caches items in a {@link HashMap}.
 * It allows to provide key or certificates dynamically via a {@link #callback} that can be set using
 * {@link #setMissingItemCallback(OpenPGPKeyMaterialProvider)}.
 * Results from this callback are automatically cached for later access. This behavior can be adjusted via
 * {@link #setCacheResultsFromCallback(boolean)}.
 *
 * @param <M> {@link OpenPGPCertificate} or {@link OpenPGPKey}
 */
public abstract class OpenPGPKeyMaterialPool<M extends OpenPGPCertificate>
        implements OpenPGPKeyMaterialProvider<M>
{
    private final Map<KeyIdentifier, M> pool = new HashMap<KeyIdentifier, M>();
    private OpenPGPKeyMaterialProvider<M> callback = null;
    private boolean cacheResultsFromCallback = true;

    /**
     * Create an empty pool.
     */
    public OpenPGPKeyMaterialPool()
    {

    }

    /**
     * Create a pool from the single provided item.
     * @param item item
     */
    public OpenPGPKeyMaterialPool(M item)
    {
        addItem(item);
    }

    /**
     * Create a pool and initialize its contents with the provided collection of items.
     * @param items collection of keys or certificates
     */
    public OpenPGPKeyMaterialPool(Collection<M> items)
    {
        for (M item : items)
        {
            addItem(item);
        }
    }

    /**
     * Set a callback that gets fired whenever an item is requested, which is not found in the pool.
     *
     * @param callback callback
     * @return this
     */
    public OpenPGPKeyMaterialPool<M> setMissingItemCallback(OpenPGPKeyMaterialProvider<M> callback)
    {
        if (callback == null)
        {
            throw new NullPointerException();
        }
        this.callback = callback;
        return this;
    }

    /**
     * Decide, whether the implementation should add {@link OpenPGPCertificate certificates} returned by
     * {@link #callback} to the pool of cached certificates.
     *
     * @param cacheResults if true, cache certificates from callback
     * @return this
     */
    public OpenPGPKeyMaterialPool<M> setCacheResultsFromCallback(boolean cacheResults)
    {
        this.cacheResultsFromCallback = cacheResults;
        return this;
    }

    @Override
    public M provide(KeyIdentifier componentKeyIdentifier)
    {
        M result = pool.get(componentKeyIdentifier);
        if (result == null && callback != null)
        {
            // dynamically request certificate or key from callback
            result = callback.provide(componentKeyIdentifier);
            if (cacheResultsFromCallback)
            {
                addItem(result);
            }
        }
        return result;
    }

    /**
     * Add a certificate to the pool.
     * Note: If multiple items share the same subkey material, adding an item might overwrite the reference to
     * another item for that subkey.
     *
     * @param item OpenPGP key or certificate that shall be added into the pool
     * @return this
     */
    public OpenPGPKeyMaterialPool<M> addItem(M item)
    {
        if (item != null)
        {
            for (Iterator<KeyIdentifier> it = item.getAllKeyIdentifiers().iterator(); it.hasNext();)
            {
                pool.put(it.next(), item);
            }
        }
        return this;
    }

    /**
     * Return all items from the pool.
     * @return all items
     */
    public Collection<M> getAllItems()
    {
        Stream<M> distinct = pool.values().stream().distinct();
        return distinct.collect(Collectors.<M>toList());
    }

    /**
     * Implementation of {@link OpenPGPKeyMaterialPool} tailored to provide {@link OpenPGPKey OpenPGPKeys}.
     */
    public static class OpenPGPKeyPool
            extends OpenPGPKeyMaterialPool<OpenPGPKey>
            implements OpenPGPKeyProvider
    {
        public OpenPGPKeyPool()
        {
            super();
        }

        public OpenPGPKeyPool(Collection<OpenPGPKey> items)
        {
            super(items);
        }

        @Override
        public OpenPGPKeyPool setMissingItemCallback(OpenPGPKeyMaterialProvider<OpenPGPKey> callback)
        {
            super.setMissingItemCallback(callback);
            return this;
        }

        @Override
        public OpenPGPKeyPool setCacheResultsFromCallback(boolean cacheResults)
        {
            super.setCacheResultsFromCallback(cacheResults);
            return this;
        }

        @Override
        public OpenPGPKeyPool addItem(OpenPGPKey item)
        {
            super.addItem(item);
            return this;
        }
    }

    /**
     * Implementation of {@link OpenPGPKeyMaterialPool} tailored to providing
     * {@link OpenPGPCertificate OpenPGPCertificates}.
     */
    public static class OpenPGPCertificatePool
            extends OpenPGPKeyMaterialPool<OpenPGPCertificate>
            implements OpenPGPCertificateProvider
    {
        public OpenPGPCertificatePool()
        {
            super();
        }

        public OpenPGPCertificatePool(Collection<OpenPGPCertificate> items)
        {
            super(items);
        }

        @Override
        public OpenPGPCertificatePool setMissingItemCallback(OpenPGPKeyMaterialProvider<OpenPGPCertificate> callback)
        {
            super.setMissingItemCallback(callback);
            return this;
        }

        @Override
        public OpenPGPCertificatePool setCacheResultsFromCallback(boolean cacheResults)
        {
            super.setCacheResultsFromCallback(cacheResults);
            return this;
        }

        @Override
        public OpenPGPCertificatePool addItem(OpenPGPCertificate item)
        {
            super.addItem(item);
            return this;
        }
    }
}
