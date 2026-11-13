package org.bouncycastle.openpgp.smartcard;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.PublicKeyDataDecryptorFactoryProvider;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.api.operator.PGPContentSignerBuilderProviderFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.smartcard.card.CardException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

/**
 * Manager aggregating one or more {@link OpenPGPSmartCardBackend backends}.
 * <p>
 * This class implements {@link PublicKeyDataDecryptorFactoryProvider}, so it can be registered with
 * {@link org.bouncycastle.openpgp.api.OpenPGPMessageProcessor#addPublicKeyDataDecryptorFactoryProvider(PublicKeyDataDecryptorFactoryProvider)}
 * to add smart-card message decryption to BC's high-level OpenPGP API. Note that the (stubbed, external)
 * {@link OpenPGPKey} still has to be added as a decryption key.
 */
public class OpenPGPSmartCardManager
    implements PublicKeyDataDecryptorFactoryProvider,
        PGPContentSignerBuilderProviderFactory
{
    private final Set<OpenPGPSmartCardBackend<?>> backends = new LinkedHashSet<OpenPGPSmartCardBackend<?>>();

    /**
     * Return a {@link Set} of all registered {@link OpenPGPSmartCardBackend backends}.
     *
     * @return set of backends
     */
    public Set<OpenPGPSmartCardBackend<?>> getBackends()
    {
        return new LinkedHashSet<OpenPGPSmartCardBackend<?>>(backends);
    }

    /**
     * Add a {@link OpenPGPSmartCardBackend} to the manager.
     *
     * @param backend OpenPGP smart card backend
     * @return this
     */
    public OpenPGPSmartCardManager addBackend(OpenPGPSmartCardBackend<?> backend)
    {
        this.backends.add(backend);
        return this;
    }

    /**
     * Add a {@link OpenPGPSmartCardBackend} at the given index to the manager.
     *
     * @param index desired index at which the backend shall be inserted.
     * @param backend backend
     * @return this
     * @throws IndexOutOfBoundsException if the index is out of bounds.
     */
    public OpenPGPSmartCardManager addBackend(int index, OpenPGPSmartCardBackend<?> backend)
    {
        // Put all registered backends in a list, insert the backend at the given index, clear the original set
        //  and re-insert all items from the list.
        List<OpenPGPSmartCardBackend<?>> list = new ArrayList<>(backends);
        list.add(index, backend);
        this.backends.clear();
        this.backends.addAll(list);
        return this;
    }

    /**
     * List all available {@link OpenPGPSmartCard smart cards} across all backends.
     *
     * @return list of all smart cards
     * @throws CardException if communication with some card fails
     * @throws IOException in case of an IO error
     */
    public List<OpenPGPSmartCard> listSmartCards()
        throws CardException, IOException
    {
        List<OpenPGPSmartCard> smartCards = new ArrayList<OpenPGPSmartCard>();
        for (Iterator<OpenPGPSmartCardBackend<?>> it = backends.iterator(); it.hasNext();)
        {
            smartCards.addAll(it.next().listSmartCards());
        }
        return smartCards;
    }

    /**
     * Return the smart card with the given serial number.
     * Note: This method iterates over all registered {@link OpenPGPSmartCardBackend} instances in the order they were
     * inserted, so if there are multiple backends managing the same smart card, backends with a lower index take
     * precedence.
     * If no matching smart card is found, throw a {@link NoSuchElementException}.
     *
     * @param serialNumber device serial number
     * @return matching smart card
     * @throws NoSuchElementException if no backend reports a card with that serial number
     * @throws CardException if communication with a card fails
     * @throws IOException in case of an IO error
     */
    public OpenPGPSmartCard findSmartCard(Integer serialNumber)
        throws CardException, IOException
    {
        for (Iterator<OpenPGPSmartCardBackend<?>> it = backends.iterator(); it.hasNext();)
        {
            OpenPGPSmartCard card = it.next().findSmartCard(serialNumber);
            if (card != null)
            {
                return card;
            }
        }
        throw new NoSuchElementException("Cannot find smart card with serial number " + serialNumber);
    }

    /**
     * Ask each registered backend in turn for a decryptor factory, returning the first one produced.
     * A backend that has no card for this key contributes null and the next backend is tried; a backend
     * that fails outright does not stop the remaining backends from being asked, but its exception is
     * kept and rethrown if no backend can serve the key - so the caller sees the real reason (wrong PIN,
     * card locked, communication failure) rather than a bare "no factory".
     *
     * @param stubbedDecryptionKey secret key the message was encrypted to
     * @param userPinProvider callback supplying the device PIN
     * @return a decryptor factory, or null if no backend has a matching card
     * @throws PGPException if every backend that recognized the key failed to produce a factory
     */
    public PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
        OpenPGPKey.OpenPGPSecretKey stubbedDecryptionKey,
        KeyPassphraseProvider userPinProvider)
        throws PGPException
    {
        PGPException lastException = null;
        for (Iterator<OpenPGPSmartCardBackend<?>> it = backends.iterator(); it.hasNext();)
        {
            OpenPGPSmartCardBackend<?> backend = it.next();
            try
            {
                PublicKeyDataDecryptorFactory factory =
                    backend.providePublicKeyDataDecryptorFactory(stubbedDecryptionKey, userPinProvider);
                if (factory != null)
                {
                    return factory;
                }
            }
            catch (NoSuchElementException e)
            {
                // this backend has no card holding the key - try the next one
            }
            catch (PGPException e)
            {
                if (lastException == null)
                {
                    lastException = e;
                }
            }
        }

        if (lastException != null)
        {
            throw lastException;
        }
        return null;
    }

    /**
     * Ask each registered backend in turn for a content signer builder provider, returning the first one produced.
     * A backend that has no card for this key contributes null and the next backend is tried; a backend
     * that fails outright does not stop the remaining backends from being asked, but its exception is
     * kept and rethrown if no backend can serve the key - so the caller sees the real reason (wrong PIN,
     * card locked, communication failure) rather than a bare "no provider".
     *
     * @param stubbedSigningKey stubbed secret key the message will be signed with
     * @param userPinProvider callback supplying the device PIN
     * @return a content signer builder provider, or null if no backend has a matching card
     * @throws PGPException if every backend that recognized the key failed to produce a provider
     */
    @Override
    public PGPContentSignerBuilderProvider getPGPContentSignerBuilderProvider(
            OpenPGPKey.OpenPGPSecretKey stubbedSigningKey,
            KeyPassphraseProvider userPinProvider,
            int hashAlgorithmId)
            throws PGPException
    {
        PGPException lastException = null;
        for (Iterator<OpenPGPSmartCardBackend<?>> it = backends.iterator(); it.hasNext();)
        {
            OpenPGPSmartCardBackend<?> backend = it.next();
            try
            {
                PGPContentSignerBuilderProvider contentSignerBuilderProvider =
                        backend.getPGPContentSignerBuilderProvider(
                                stubbedSigningKey, userPinProvider, hashAlgorithmId);
                if (contentSignerBuilderProvider != null)
                {
                    return contentSignerBuilderProvider;
                }
            }
            catch (NoSuchElementException e)
            {
                // this backend has no card holding the key - try the next one
            }
            catch (PGPException e)
            {
                if (lastException == null)
                {
                    lastException = e;
                }
            }
        }

        if (lastException != null)
        {
            throw lastException;
        }
        return null;
    }
}
