package org.bouncycastle.smartcard;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactoryProvider;
import org.bouncycastle.smartcard.card.CardException;

import java.io.IOException;
import java.util.*;

/**
 * Manager class for OpenPGP Smart Cards.
 * <p>
 * This class implements {@link PublicKeyDataDecryptorFactoryProvider}, so it can be used to add message decryption
 * support in BC's high level OpenPGP API via {@link org.bouncycastle.openpgp.api.OpenPGPMessageProcessor#addPublicKeyDataDecryptorFactoryProvider(PublicKeyDataDecryptorFactoryProvider)}.
 * Note though, that you still need to add the (stubbed) {@link OpenPGPKey} as decryption key.
 */
@SuppressWarnings("rawtypes")
public class OpenPGPSmartCardManager
        implements PublicKeyDataDecryptorFactoryProvider
{

    private final Set<OpenPGPSmartCardBackend> backends = new LinkedHashSet<>();

    public OpenPGPSmartCardManager()
    {

    }

    /**
     * Return a {@link Set} of all available {@link OpenPGPSmartCardBackend backends}.
     *
     * @return set of backends
     */
    public Set<OpenPGPSmartCardBackend> getBackends()
    {
        return new LinkedHashSet<>(backends);
    }

    /**
     * Add a {@link OpenPGPSmartCardBackend} to the manager.
     *
     * @param backend OpenPGP smart card backend
     * @return this
     */
    public OpenPGPSmartCardManager addBackend(OpenPGPSmartCardBackend backend)
    {
        this.backends.add(backend);
        return this;
    }

    /**
     * List all available {@link OpenPGPSmartCard smart cards} across all backends.
     *
     * @return list of all smart cards
     * @throws PGPException if
     * @throws CardException if communication with some card fails
     * @throws IOException in case of an IO error
     */
    public List<OpenPGPSmartCard> listSmartCards()
            throws PGPException, CardException, IOException
    {
        List<OpenPGPSmartCard> smartCards = new ArrayList<>();
        for (OpenPGPSmartCardBackend backend : this.backends)
        {
            smartCards.addAll(backend.listSmartCards());
        }
        return smartCards;
    }

    public OpenPGPSmartCard findSmartCard(Integer serialNumber)
            throws CardException, IOException
    {
        for (OpenPGPSmartCardBackend backend : this.backends)
        {
            OpenPGPSmartCard card = backend.findSmartCard(serialNumber);
            if (card != null)
            {
                return card;
            }
        }
        throw new NoSuchElementException("Cannot find smart card with serial number " + serialNumber);
    }

    @Override
    public PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
            OpenPGPKey.OpenPGPSecretKey secretKey,
            KeyPassphraseProvider passphraseProvider)
    {
        for (OpenPGPSmartCardBackend backend : this.backends)
        {
            try
            {
                return backend.providePublicKeyDataDecryptorFactory(secretKey, passphraseProvider);
            }
            catch (PGPException e)
            {
                // -DM System.out.println
                System.out.println(e.getMessage());
            }
        }
        return null;
    }
}
