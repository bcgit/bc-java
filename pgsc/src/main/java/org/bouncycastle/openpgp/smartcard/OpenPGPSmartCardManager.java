package org.bouncycastle.openpgp.smartcard;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.PublicKeyDataDecryptorFactoryProvider;
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
    implements PublicKeyDataDecryptorFactoryProvider
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
     * @param secretKey secret key the message was encrypted to
     * @param passphraseProvider callback supplying the device PIN
     * @return a decryptor factory, or null if no backend has a matching card
     * @throws PGPException if every backend that recognised the key failed to produce a factory
     */
    public PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
        OpenPGPKey.OpenPGPSecretKey secretKey,
        KeyPassphraseProvider passphraseProvider)
        throws PGPException
    {
        PGPException lastException = null;
        for (Iterator<OpenPGPSmartCardBackend<?>> it = backends.iterator(); it.hasNext();)
        {
            OpenPGPSmartCardBackend<?> backend = it.next();
            try
            {
                PublicKeyDataDecryptorFactory factory =
                    backend.providePublicKeyDataDecryptorFactory(secretKey, passphraseProvider);
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
}
