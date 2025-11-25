package org.bouncycastle.openpgp.api;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.FingerprintUtil;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureException;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.api.exception.IncorrectOpenPGPSignatureException;
import org.bouncycastle.openpgp.api.exception.MalformedOpenPGPSignatureException;
import org.bouncycastle.openpgp.api.exception.MissingIssuerCertException;
import org.bouncycastle.openpgp.api.util.UTCUtil;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;

/**
 * OpenPGP certificates (TPKs - transferable public keys) are long-living structures that may change during
 * their lifetime. A key-holder may add new components like subkeys or identities, along with associated
 * binding self-signatures to the certificate and old components may expire / get revoked at some point.
 * Since any such changes may have an influence on whether a data signature is valid at a given time, or what subkey
 * should be used when generating an encrypted / signed message, an API is needed that provides a view on the
 * certificate that takes into consideration a relevant window in time.
 * <p>
 * Compared to a {@link PGPPublicKeyRing}, an {@link OpenPGPCertificate} has been evaluated at (or rather for)
 * a given evaluation time. It offers a clean API for accessing the key-holder's preferences at a specific
 * point in time and makes sure, that relevant self-signatures on certificate components are validated and verified.
 *
 * @see <a href="https://openpgp.dev/book/certificates.html#">OpenPGP for Application Developers - Chapter 4</a>
 * for background information on the terminology used in this class.
 */
public class OpenPGPCertificate
{
    final OpenPGPImplementation implementation;
    final OpenPGPPolicy policy;

    protected PGPKeyRing keyRing;

    private final OpenPGPPrimaryKey primaryKey;
    private final Map<KeyIdentifier, OpenPGPSubkey> subkeys;

    // Note: get() needs to be accessed with OpenPGPCertificateComponent.getPublicComponent() to ensure
    //  proper functionality with secret key components.
    private final Map<OpenPGPCertificateComponent, OpenPGPSignatureChains> componentSignatureChains;

    /**
     * Instantiate an {@link OpenPGPCertificate} from a passed {@link PGPKeyRing} using the default
     * {@link OpenPGPImplementation} and its {@link OpenPGPPolicy}.
     *
     * @param keyRing key ring
     */
    public OpenPGPCertificate(PGPKeyRing keyRing)
    {
        this(keyRing, OpenPGPImplementation.getInstance());
    }

    /**
     * Instantiate an {@link OpenPGPCertificate} from a parsed {@link PGPKeyRing}
     * using the provided {@link OpenPGPImplementation} and its {@link OpenPGPPolicy}.
     *
     * @param keyRing        public key ring
     * @param implementation OpenPGP implementation
     */
    public OpenPGPCertificate(PGPKeyRing keyRing, OpenPGPImplementation implementation)
    {
        this(keyRing, implementation, implementation.policy());
    }

    /**
     * Instantiate an {@link OpenPGPCertificate} from a parsed {@link PGPKeyRing}
     * using the provided {@link OpenPGPImplementation} and provided {@link OpenPGPPolicy}.
     *
     * @param keyRing        public key ring
     * @param implementation OpenPGP implementation
     * @param policy         OpenPGP policy
     */
    public OpenPGPCertificate(PGPKeyRing keyRing, OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        this.implementation = implementation;
        this.policy = policy;

        this.keyRing = keyRing;
        this.subkeys = new LinkedHashMap<KeyIdentifier, OpenPGPSubkey>();
        this.componentSignatureChains = new LinkedHashMap<OpenPGPCertificateComponent, OpenPGPSignatureChains>();

        Iterator<PGPPublicKey> rawKeys = keyRing.getPublicKeys();

        PGPPublicKey rawPrimaryKey = rawKeys.next();
        this.primaryKey = new OpenPGPPrimaryKey(rawPrimaryKey, this);
        processPrimaryKey(primaryKey);

        while (rawKeys.hasNext())
        {
            PGPPublicKey rawSubkey = rawKeys.next();
            OpenPGPSubkey subkey = new OpenPGPSubkey(rawSubkey, this);
            subkeys.put(rawSubkey.getKeyIdentifier(), subkey);
            processSubkey(subkey);
        }
    }

    /**
     * Return true, if this object is an {@link OpenPGPKey}, false otherwise.
     *
     * @return true if this is a secret key
     */
    public boolean isSecretKey()
    {
        return false;
    }

    /**
     * Return a {@link List} of all {@link OpenPGPUserId OpenPGPUserIds} on the certificate, regardless of their
     * validity.
     *
     * @return all user ids
     */
    public List<OpenPGPUserId> getAllUserIds()
    {
        return getPrimaryKey().getUserIDs();
    }

    /**
     * Return a {@link List} of all valid {@link OpenPGPUserId OpenPGPUserIds} on the certificate.
     *
     * @return valid user ids
     */
    public List<OpenPGPUserId> getValidUserIds()
    {
        return getValidUserIds(new Date());
    }

    /**
     * Return a {@link List} containing all {@link OpenPGPUserId OpenPGPUserIds} that are valid at the given
     * evaluation time.
     *
     * @param evaluationTime reference time
     * @return user ids that are valid at the given evaluation time
     */
    public List<OpenPGPUserId> getValidUserIds(Date evaluationTime)
    {
        return getPrimaryKey().getValidUserIDs(evaluationTime);
    }

    /**
     * Get a {@link Map} of all public {@link OpenPGPComponentKey component keys} keyed by their {@link KeyIdentifier}.
     *
     * @return all public keys
     */
    public Map<KeyIdentifier, OpenPGPComponentKey> getPublicKeys()
    {
        Map<KeyIdentifier, OpenPGPComponentKey> keys = new LinkedHashMap<KeyIdentifier, OpenPGPComponentKey>();
        keys.put(primaryKey.getKeyIdentifier(), primaryKey);
        keys.putAll(subkeys);
        return keys;
    }

    /**
     * Return the primary key of the certificate.
     *
     * @return primary key
     */
    public OpenPGPPrimaryKey getPrimaryKey()
    {
        return primaryKey;
    }

    /**
     * Return a {@link Map} containing the subkeys of this certificate, keyed by their {@link KeyIdentifier}.
     * Note: This map does NOT contain the primary key ({@link #getPrimaryKey()}).
     *
     * @return subkeys
     */
    public Map<KeyIdentifier, OpenPGPSubkey> getSubkeys()
    {
        return new LinkedHashMap<KeyIdentifier, OpenPGPSubkey>(subkeys);
    }

    /**
     * Return a {@link List} containing all {@link OpenPGPComponentKey component keys} that carry any of the
     * given key flags at evaluation time.
     * <b>
     * Note: To get all component keys that have EITHER {@link KeyFlags#ENCRYPT_COMMS} OR {@link KeyFlags#ENCRYPT_STORAGE},
     * call this method like this:
     * <pre>
     * keys = getComponentKeysWithFlag(date, KeyFlags.ENCRYPT_COMMS, KeyFlags.ENCRYPT_STORAGE);
     * </pre>
     * If you instead want to access all keys, that have BOTH flags, you need to <pre>&amp;</pre> both flags:
     * <pre>
     * keys = getComponentKeysWithFlag(date, KeyFlags.ENCRYPT_COMMS &amp; KeyFlags.ENCRYPT_STORAGE);
     * </pre>
     *
     * @param evaluationTime reference time
     * @param keyFlags       key flags
     * @return list of keys that carry any of the given key flags at evaluation time
     */
    public List<OpenPGPComponentKey> getComponentKeysWithFlag(Date evaluationTime, final int... keyFlags)
    {
        return filterKeys(evaluationTime, new KeyFilter()
        {
            @Override
            public boolean test(OpenPGPComponentKey key, Date time)
            {
                return key.hasKeyFlags(time, keyFlags);
            }
        });
    }

    /**
     * Return a {@link List} containing all {@link OpenPGPCertificateComponent components} of the certificate.
     * Components are primary key, subkeys and identities (user-ids, user attributes).
     *
     * @return list of components
     */
    public List<OpenPGPCertificateComponent> getComponents()
    {
        return new ArrayList<OpenPGPCertificateComponent>(componentSignatureChains.keySet());
    }

    /**
     * Return all {@link OpenPGPComponentKey OpenPGPComponentKeys} in the certificate.
     * The return value is a {@link List} containing the {@link OpenPGPPrimaryKey} and all
     * {@link OpenPGPSubkey OpenPGPSubkeys}.
     *
     * @return list of all component keys
     */
    public List<OpenPGPComponentKey> getKeys()
    {
        List<OpenPGPComponentKey> keys = new ArrayList<OpenPGPComponentKey>();
        keys.add(primaryKey);
        keys.addAll(subkeys.values());
        return keys;
    }

    /**
     * Return a {@link List} of all {@link OpenPGPComponentKey component keys} that are valid right now.
     *
     * @return all valid keys
     */
    public List<OpenPGPComponentKey> getValidKeys()
    {
        return getValidKeys(new Date());
    }

    /**
     * Return a {@link List} of all {@link OpenPGPComponentKey component keys} that are valid at the given
     * evaluation time.
     *
     * @param evaluationTime reference time
     * @return all keys that are valid at evaluation time
     */
    public List<OpenPGPComponentKey> getValidKeys(Date evaluationTime)
    {
        return filterKeys(evaluationTime, new KeyFilter()
        {
            @Override
            public boolean test(OpenPGPComponentKey key, Date time)
            {
                return true;
            }
        });
    }

    /**
     * Return the {@link OpenPGPComponentKey} identified by the passed in {@link KeyIdentifier}.
     *
     * @param identifier key identifier
     * @return component key
     */
    public OpenPGPComponentKey getKey(KeyIdentifier identifier)
    {
        if (identifier.matchesExplicit(getPrimaryKey().getPGPPublicKey().getKeyIdentifier()))
        {
            return primaryKey;
        }

        return subkeys.get(identifier);
    }

    /**
     * Return the {@link OpenPGPComponentKey} that likely issued the passed in {@link PGPSignature}.
     *
     * @param signature signature
     * @return issuer (sub-)key
     */
    public OpenPGPComponentKey getSigningKeyFor(PGPSignature signature)
    {
        List<KeyIdentifier> keyIdentifiers = signature.getKeyIdentifiers();

        // Subkey binding signatures do not require issuer
        int type = signature.getSignatureType();
        if (type == PGPSignature.SUBKEY_BINDING ||
            type == PGPSignature.SUBKEY_REVOCATION)
        {
            return primaryKey;
        }

        // issuer is primary key
        if (KeyIdentifier.matches(keyIdentifiers, getPrimaryKey().getKeyIdentifier(), true))
        {
            return primaryKey;
        }

        for (Iterator<KeyIdentifier> it = subkeys.keySet().iterator(); it.hasNext(); )
        {
            KeyIdentifier subkeyIdentifier = it.next();
            if (KeyIdentifier.matches(keyIdentifiers, subkeyIdentifier, true))
            {
                return subkeys.get(subkeyIdentifier);
            }
        }

        return null; // external issuer
    }

    /**
     * Return the {@link PGPKeyRing} that this certificate is based on.
     *
     * @return underlying key ring
     */
    public PGPKeyRing getPGPKeyRing()
    {
        return keyRing;
    }

    /**
     * Return the underlying {@link PGPPublicKeyRing}.
     *
     * @return public keys
     */
    public PGPPublicKeyRing getPGPPublicKeyRing()
    {
        if (keyRing instanceof PGPPublicKeyRing)
        {
            return (PGPPublicKeyRing)keyRing;
        }

        List<PGPPublicKey> list = new ArrayList<PGPPublicKey>();
        for (Iterator<PGPPublicKey> it = keyRing.getPublicKeys(); it.hasNext(); )
        {
            list.add(it.next());
        }
        return new PGPPublicKeyRing(list);
    }

    /**
     * Return the {@link KeyIdentifier} of the certificates primary key.
     *
     * @return primary key identifier
     */
    public KeyIdentifier getKeyIdentifier()
    {
        return primaryKey.getKeyIdentifier();
    }

    /**
     * Return a list of ALL (sub-)key's identifiers, including those of expired / revoked / unbound keys.
     *
     * @return all keys identifiers
     */
    public List<KeyIdentifier> getAllKeyIdentifiers()
    {
        List<KeyIdentifier> identifiers = new ArrayList<KeyIdentifier>();
        for (Iterator<PGPPublicKey> it = keyRing.getPublicKeys(); it.hasNext(); )
        {
            PGPPublicKey key = it.next();
            identifiers.add(key.getKeyIdentifier());
        }
        return identifiers;
    }

    /**
     * Return the current self-certification signature.
     * This is either a DirectKey signature on the primary key, or the latest self-certification on
     * a {@link OpenPGPUserId}.
     *
     * @return latest certification signature
     */
    public OpenPGPComponentSignature getCertification()
    {
        return getCertification(new Date());
    }

    /**
     * Return the most recent self-certification signature at evaluation time.
     * This is either a DirectKey signature on the primary key, or the (at evaluation time) latest
     * self-certification on an {@link OpenPGPUserId}.
     *
     * @param evaluationTime reference time
     * @return latest certification signature
     */
    public OpenPGPComponentSignature getCertification(Date evaluationTime)
    {
        return primaryKey.getCertification(evaluationTime);
    }

    /**
     * Return the most recent revocation signature on the certificate.
     * This is either a KeyRevocation signature on the primary key, or the latest certification revocation
     * signature on an {@link OpenPGPUserId}.
     *
     * @return latest certification revocation
     */
    public OpenPGPComponentSignature getRevocation()
    {
        return getRevocation(new Date());
    }

    /**
     * Return the (at evaluation time) most recent revocation signature on the certificate.
     * This is either a KeyRevocation signature on the primary key, or the latest certification revocation
     * signature on an {@link OpenPGPUserId}.
     *
     * @param evaluationTime reference time
     * @return latest certification revocation
     */
    public OpenPGPComponentSignature getRevocation(Date evaluationTime)
    {
        return primaryKey.getRevocation(evaluationTime);
    }

    /**
     * Return the last time, the key was modified (before right now).
     * A modification is the addition of a new subkey, or key signature.
     *
     * @return last modification time
     */
    public Date getLastModificationDate()
    {
        return getLastModificationDateAt(new Date());
    }

    /**
     * Return the last time, the key was modified before or at the given evaluation time.
     *
     * @param evaluationTime evaluation time
     * @return last modification time before or at evaluation time
     */
    public Date getLastModificationDateAt(Date evaluationTime)
    {
        Date latestModification = null;
        // Signature creation times
        for (Iterator<OpenPGPCertificateComponent> it = getComponents().iterator(); it.hasNext(); )
        {
            OpenPGPSignatureChains componentChains = getAllSignatureChainsFor(it.next());

            componentChains = componentChains.getChainsAt(evaluationTime);
            for (Iterator<OpenPGPSignatureChain> it2 = componentChains.iterator(); it2.hasNext(); )
            {
                for (Iterator<OpenPGPSignatureChain.Link> it3 = it2.next().iterator(); it3.hasNext(); )
                {
                    OpenPGPSignatureChain.Link link = it3.next();
                    if (latestModification == null || link.since().after(latestModification))
                    {
                        latestModification = link.since();
                    }
                }
            }
        }

        if (latestModification != null)
        {
            return latestModification;
        }

        // Key creation times
        for (Iterator<OpenPGPComponentKey> it = getKeys().iterator(); it.hasNext(); )
        {
            OpenPGPComponentKey key = it.next();
            if (key.getCreationTime().after(evaluationTime))
            {
                continue;
            }

            if (latestModification == null || key.getCreationTime().after(latestModification))
            {
                latestModification = key.getCreationTime();
            }
        }
        return latestModification;
    }

    /**
     * Join two copies of the same {@link OpenPGPCertificate}, merging its {@link OpenPGPCertificateComponent components}
     * into a single instance.
     * The ASCII armored {@link String} might contain more than one {@link OpenPGPCertificate}.
     * Items that are not a copy of the base certificate are silently ignored.
     *
     * @param certificate base certificate
     * @param armored     ASCII armored {@link String} containing one or more copies of the same certificate,
     *                    possibly containing a different set of components
     * @return merged certificate
     * @throws IOException  if the armored data cannot be processed
     * @throws PGPException if a protocol level error occurs
     */
    public static OpenPGPCertificate join(OpenPGPCertificate certificate, String armored)
        throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(armored.getBytes());
        InputStream decoderStream = PGPUtil.getDecoderStream(bIn);
        BCPGInputStream wrapper = BCPGInputStream.wrap(decoderStream);
        PGPObjectFactory objFac = certificate.implementation.pgpObjectFactory(wrapper);

        Object next;
        while ((next = objFac.nextObject()) != null)
        {
            if (next instanceof PGPPublicKeyRing)
            {
                PGPPublicKeyRing publicKeys = (PGPPublicKeyRing)next;
                OpenPGPCertificate otherCert = new OpenPGPCertificate(publicKeys, certificate.implementation);
                try
                {
                    return join(certificate, otherCert);
                }
                catch (IllegalArgumentException e)
                {
                    // skip over wrong certificate
                }
            }

            else if (next instanceof PGPSecretKeyRing)
            {
                throw new IllegalArgumentException("Joining with a secret key is not supported.");
            }

            else if (next instanceof PGPSignatureList)
            {
                // parse and join delegations / revocations
                // those are signatures of type DIRECT_KEY or KEY_REVOCATION issued either by the primary key itself
                // (self-signatures) or by a 3rd party (delegations / delegation revocations)
                PGPSignatureList signatures = (PGPSignatureList)next;

                PGPPublicKeyRing publicKeys = certificate.getPGPPublicKeyRing();
                PGPPublicKey primaryKey = publicKeys.getPublicKey();
                for (Iterator<PGPSignature> it = signatures.iterator(); it.hasNext(); )
                {
                    primaryKey = PGPPublicKey.addCertification(primaryKey, it.next());
                }
                publicKeys = PGPPublicKeyRing.insertPublicKey(publicKeys, primaryKey);
                return new OpenPGPCertificate(publicKeys, certificate.implementation);
            }
        }
        return null;
    }

    /**
     * Join two copies of the same {@link OpenPGPCertificate}, merging its {@link OpenPGPCertificateComponent components}
     * into a single instance.
     *
     * @param certificate base certificate
     * @param other       copy of the same certificate, potentially carrying a different set of components
     * @return merged certificate
     * @throws PGPException if a protocol level error occurs
     */
    public static OpenPGPCertificate join(OpenPGPCertificate certificate, OpenPGPCertificate other)
        throws PGPException
    {
        PGPPublicKeyRing joined = PGPPublicKeyRing.join(
            certificate.getPGPPublicKeyRing(), other.getPGPPublicKeyRing());
        return new OpenPGPCertificate(joined, certificate.implementation);
    }

    /**
     * Return the primary keys fingerprint in binary format.
     *
     * @return primary key fingerprint
     */
    public byte[] getFingerprint()
    {
        return primaryKey.getPGPPublicKey().getFingerprint();
    }

    /**
     * Return the primary keys fingerprint as a pretty-printed {@link String}.
     *
     * @return pretty-printed primary key fingerprint
     */
    public String getPrettyFingerprint()
    {
        return FingerprintUtil.prettifyFingerprint(getFingerprint());
    }

    /**
     * Return an ASCII armored {@link String} containing the certificate.
     *
     * @return armored certificate
     * @throws IOException if the cert cannot be encoded
     */
    public String toAsciiArmoredString()
        throws IOException
    {
        return toAsciiArmoredString(PacketFormat.ROUNDTRIP);
    }

    /**
     * Return an ASCII armored {@link String} containing the certificate.
     *
     * @param packetFormat packet length encoding format
     * @return armored certificate
     * @throws IOException if the cert cannot be encoded
     */
    public String toAsciiArmoredString(PacketFormat packetFormat)
        throws IOException
    {
        ArmoredOutputStream.Builder armorBuilder = ArmoredOutputStream.builder()
            .clearHeaders();
        // Add fingerprint comment
        armorBuilder.addSplitMultilineComment(getPrettyFingerprint());

        // Add user-id comments
        for (Iterator<OpenPGPUserId> it = getPrimaryKey().getUserIDs().iterator(); it.hasNext(); )
        {
            armorBuilder.addEllipsizedComment(it.next().getUserId());
        }

        return toAsciiArmoredString(packetFormat, armorBuilder);
    }

    /**
     * Return an ASCII armored {@link String} containing the certificate.
     * The {@link ArmoredOutputStream.Builder} can be used to customize the ASCII armor (headers, CRC etc.).
     *
     * @param packetFormat packet length encoding format
     * @param armorBuilder builder for the ASCII armored output stream
     * @return armored certificate
     * @throws IOException if the cert cannot be encoded
     */
    public String toAsciiArmoredString(PacketFormat packetFormat, ArmoredOutputStream.Builder armorBuilder)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = armorBuilder.build(bOut);

        aOut.write(getEncoded(packetFormat));
        aOut.close();
        return bOut.toString();
    }

    /**
     * Return a byte array containing the binary representation of the certificate.
     *
     * @return binary encoded certificate
     * @throws IOException if the certificate cannot be encoded
     */
    public byte[] getEncoded()
        throws IOException
    {
        return getEncoded(PacketFormat.ROUNDTRIP);
    }

    /**
     * Return a byte array containing the binary representation of the certificate, encoded using the
     * given packet length encoding format.
     *
     * @param format packet length encoding format
     * @return binary encoded certificate
     * @throws IOException if the certificate cannot be encoded
     */
    public byte[] getEncoded(PacketFormat format)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, format);

        // Make sure we export a TPK
        List<PGPPublicKey> list = new ArrayList<PGPPublicKey>();
        for (Iterator<PGPPublicKey> it = getPGPKeyRing().getPublicKeys(); it.hasNext(); )
        {
            list.add(it.next());
        }
        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(list);

        publicKeys.encode(pOut, true);
        pOut.close();
        return bOut.toByteArray();
    }

    private OpenPGPSignatureChain getSignatureChainFor(OpenPGPCertificateComponent component,
                                                       OpenPGPComponentKey origin,
                                                       Date evaluationDate)
    {
        // Check if there are signatures at all for the component
        OpenPGPSignatureChains chainsForComponent = getAllSignatureChainsFor(component);
        boolean isPrimaryKey = component == getPrimaryKey();
        if (isPrimaryKey && chainsForComponent.getCertificationAt(evaluationDate) == null)
        {
            // If cert has no direct-key signatures, consider primary UID bindings instead
            OpenPGPUserId primaryUserId = getPrimaryUserId(evaluationDate);
            if (primaryUserId != null)
            {
                chainsForComponent.addAll(getAllSignatureChainsFor(primaryUserId));
            }
        }

        // Isolate chains which originate from the passed origin key component
        OpenPGPSignatureChains fromOrigin = chainsForComponent.fromOrigin(origin);
        if (fromOrigin == null)
        {
            return null;
        }

        // Return chain that currently takes precedence
        return fromOrigin.getChainAt(evaluationDate);
    }

    /**
     * Return all {@link OpenPGPSignatureChain OpenPGPSignatureChains} binding the given
     * {@link OpenPGPCertificateComponent}.
     *
     * @param component certificate component
     * @return all chains of the component
     */
    private OpenPGPSignatureChains getAllSignatureChainsFor(OpenPGPCertificateComponent component)
    {
        OpenPGPSignatureChains chains = new OpenPGPSignatureChains(component.getPublicComponent());
        chains.addAll(componentSignatureChains.get(component.getPublicComponent()));
        return chains;
    }

    /**
     * Process the given {@link OpenPGPPrimaryKey}, parsing all its signatures and identities.
     *
     * @param primaryKey primary key
     */
    private void processPrimaryKey(OpenPGPPrimaryKey primaryKey)
    {
        OpenPGPSignatureChains keySignatureChains = new OpenPGPSignatureChains(primaryKey);
        List<OpenPGPComponentSignature> keySignatures = primaryKey.getKeySignatures();

        // Key Signatures
        addSignaturesToChains(keySignatures, keySignatureChains);
        componentSignatureChains.put(primaryKey, keySignatureChains);

        // Identities
        for (Iterator<OpenPGPIdentityComponent> it = primaryKey.identityComponents.iterator(); it.hasNext(); )
        {
            OpenPGPIdentityComponent identity = it.next();
            OpenPGPSignatureChains identityChains = new OpenPGPSignatureChains(identity);
            List<OpenPGPComponentSignature> bindings;

            if (identity instanceof OpenPGPUserId)
            {
                bindings = primaryKey.getUserIdSignatures((OpenPGPUserId)identity);
            }
            else
            {
                bindings = primaryKey.getUserAttributeSignatures((OpenPGPUserAttribute)identity);
            }
            addSignaturesToChains(bindings, identityChains);
            componentSignatureChains.put(identity, identityChains);
        }
    }

    /**
     * Process the given {@link OpenPGPSubkey}, parsing all its binding signatures.
     *
     * @param subkey subkey
     */
    private void processSubkey(OpenPGPSubkey subkey)
    {
        List<OpenPGPComponentSignature> bindingSignatures = subkey.getKeySignatures();
        OpenPGPSignatureChains subkeyChains = new OpenPGPSignatureChains(subkey);

        for (Iterator<OpenPGPComponentSignature> it = bindingSignatures.iterator(); it.hasNext(); )
        {
            OpenPGPComponentSignature sig = it.next();
            OpenPGPComponentKey issuer = subkey.getCertificate().getSigningKeyFor(sig.getSignature());
            if (issuer == null)
            {
                continue; // external key
            }

            OpenPGPSignatureChains issuerChains = getAllSignatureChainsFor(issuer);
            if (!issuerChains.chains.isEmpty())
            {
                for (Iterator<OpenPGPSignatureChain> it2 = issuerChains.chains.iterator(); it2.hasNext(); )
                {
                    subkeyChains.add(it2.next().plus(sig));
                }
            }
            else
            {
                subkeyChains.add(new OpenPGPSignatureChain(OpenPGPSignatureChain.Link.create(sig)));
            }
        }
        this.componentSignatureChains.put(subkey, subkeyChains);
    }

    /**
     * Return true, if the passed in component is - at evaluation time - properly bound to the certificate.
     *
     * @param component      OpenPGP certificate component
     * @param evaluationTime evaluation time
     * @return true if component is bound at evaluation time, false otherwise
     */
    private boolean isBound(OpenPGPCertificateComponent component,
                            Date evaluationTime)
    {
        return isBoundBy(component, getPrimaryKey(), evaluationTime);
    }

    /**
     * Return true, if the passed in component is - at evaluation time - properly bound to the certificate with
     * a signature chain originating at the passed in root component.
     *
     * @param component      OpenPGP certificate component
     * @param root           root certificate component
     * @param evaluationTime evaluation time
     * @return true if component is bound at evaluation time, originating at root, false otherwise
     */
    private boolean isBoundBy(OpenPGPCertificateComponent component,
                              OpenPGPComponentKey root,
                              Date evaluationTime)
    {
        OpenPGPSignature.OpenPGPSignatureSubpacket keyExpiration =
            component.getApplyingSubpacket(evaluationTime, SignatureSubpacketTags.KEY_EXPIRE_TIME);
        if (keyExpiration != null)
        {
            KeyExpirationTime kexp = (KeyExpirationTime)keyExpiration.getSubpacket();
            if (kexp.getTime() != 0)
            {
                OpenPGPComponentKey key = component.getKeyComponent();
                Date expirationDate = new Date(1000 * kexp.getTime() + key.getCreationTime().getTime());
                if (expirationDate.before(evaluationTime))
                {
                    // Key is expired.
                    return false;
                }
            }
        }

        try
        {
            OpenPGPSignatureChain chain = getSignatureChainFor(component, root, evaluationTime);
            if (chain == null)
            {
                // Component is not bound at all
                return false;
            }

            // Chain needs to be valid (signatures correct)
            if (chain.isValid(implementation.pgpContentVerifierBuilderProvider(), policy))
            {
                // Chain needs to not contain a revocation signature, otherwise the component is considered revoked
                return !chain.isRevocation();
            }

            // Signature is not correct
            return false;
        }
        catch (PGPException e)
        {
            // Signature verification failed (signature broken?)
            return false;
        }
    }

    /**
     * Return a {@link List} containing all currently marked, valid encryption keys.
     *
     * @return encryption keys
     */
    public List<OpenPGPComponentKey> getEncryptionKeys()
    {
        return getEncryptionKeys(new Date());
    }

    /**
     * Return a list of all keys that are - at evaluation time - valid encryption keys.
     *
     * @param evaluationTime evaluation time
     * @return encryption keys
     */
    public List<OpenPGPComponentKey> getEncryptionKeys(Date evaluationTime)
    {
        return filterKeys(evaluationTime, new KeyFilter()
        {
            @Override
            public boolean test(OpenPGPComponentKey key, Date time)
            {
                return key.isEncryptionKey(time);
            }
        });
    }

    /**
     * Return a {@link List} containing all currently valid marked signing keys.
     *
     * @return list of signing keys
     */
    public List<OpenPGPComponentKey> getSigningKeys()
    {
        return getSigningKeys(new Date());
    }

    /**
     * Return a list of all keys that - at evaluation time - are validly marked as signing keys.
     *
     * @param evaluationTime evaluation time
     * @return list of signing keys
     */
    public List<OpenPGPComponentKey> getSigningKeys(Date evaluationTime)
    {
        return filterKeys(evaluationTime, new KeyFilter()
        {
            @Override
            public boolean test(OpenPGPComponentKey key, Date time)
            {
                return key.isSigningKey(time);
            }
        });
    }

    /**
     * Return a {@link List} containing all currently valid marked certification keys.
     *
     * @return list of certification keys
     */
    public List<OpenPGPComponentKey> getCertificationKeys()
    {
        return getCertificationKeys(new Date());
    }

    /**
     * Return a list of all keys that - at evaluation time - are validly marked as certification keys.
     *
     * @param evaluationTime evaluation time
     * @return list of certification keys
     */
    public List<OpenPGPComponentKey> getCertificationKeys(Date evaluationTime)
    {
        return filterKeys(evaluationTime, new KeyFilter()
        {
            @Override
            public boolean test(OpenPGPComponentKey key, Date time)
            {
                return key.isCertificationKey(time);
            }
        });
    }

    /**
     * Return {@link OpenPGPSignatureChains} that contain preference information.
     *
     * @return signature chain containing certificate-wide preferences (typically DK signature)
     */
    private OpenPGPSignatureChain getPreferenceSignature(Date evaluationTime)
    {
        OpenPGPSignatureChain directKeyBinding = getPrimaryKey().getSignatureChains()
            .fromOrigin(getPrimaryKey())
            .getCertificationAt(evaluationTime);

        if (directKeyBinding != null)
        {
            return directKeyBinding;
        }

        List<OpenPGPSignatureChain> uidBindings = new ArrayList<OpenPGPSignatureChain>();
        for (Iterator<OpenPGPUserId> it = getPrimaryKey().getUserIDs().iterator(); it.hasNext(); )
        {
            OpenPGPSignatureChain uidBinding = getAllSignatureChainsFor(it.next())
                .fromOrigin(getPrimaryKey()).getCertificationAt(evaluationTime);

            if (uidBinding != null)
            {
                uidBindings.add(uidBinding);
            }
        }

        //uidBindings.sort(Comparator.comparing(OpenPGPSignatureChain::getSince).reversed());
        uidBindings.sort(new Comparator<OpenPGPSignatureChain>()
        {
            @Override
            public int compare(OpenPGPSignatureChain o1, OpenPGPSignatureChain o2)
            {
                // Reverse comparison for descending order (mimics .reversed())
                return o2.getSince().compareTo(o1.getSince());
            }
        });
        for (Iterator<OpenPGPSignatureChain> it = uidBindings.iterator(); it.hasNext(); )
        {
            OpenPGPSignatureChain binding = it.next();
            PGPSignature sig = binding.getSignature().getSignature();
            if (sig.getHashedSubPackets().isPrimaryUserID())
            {
                return binding;
            }
        }

        return uidBindings.isEmpty() ? null : uidBindings.get(0);
    }

    /**
     * Return all identities ({@link OpenPGPUserId User IDs}, {@link OpenPGPUserAttribute User Attributes}
     * of the certificate.
     *
     * @return identities
     */
    public List<OpenPGPIdentityComponent> getIdentities()
    {
        return new ArrayList<OpenPGPIdentityComponent>(primaryKey.identityComponents);
    }

    /**
     * Return the current primary {@link OpenPGPUserId} of the certificate.
     *
     * @return primary user id
     */
    public OpenPGPUserId getPrimaryUserId()
    {
        return getPrimaryUserId(new Date());
    }

    /**
     * Return the {@link OpenPGPUserId} that is considered primary at the given evaluation time.
     *
     * @param evaluationTime evaluation time
     * @return primary user-id at evaluation time
     */
    public OpenPGPUserId getPrimaryUserId(Date evaluationTime)
    {
        return primaryKey.getExplicitOrImplicitPrimaryUserId(evaluationTime);
    }

    /**
     * Return the {@link OpenPGPUserId} object matching the given user-id {@link String}.
     *
     * @param userId user-id
     * @return user-id
     */
    public OpenPGPUserId getUserId(String userId)
    {
        for (Iterator<?> it = primaryKey.getUserIDs().iterator(); it.hasNext(); )
        {
            OpenPGPUserId uid = (OpenPGPUserId)it.next();
            if (uid.getUserId().equals(userId))
            {
                return uid;
            }
        }
        return null;
    }

    /**
     * Return the time at which the certificate expires.
     *
     * @return expiration time of the certificate
     */
    public Date getExpirationTime()
    {
        return getExpirationTime(new Date());
    }

    /**
     * Return the time at which the certificate is expected to expire, considering the given evaluation time.
     *
     * @param evaluationTime reference time
     * @return expiration time at evaluation time
     */
    public Date getExpirationTime(Date evaluationTime)
    {
        return getPrimaryKey().getKeyExpirationDateAt(evaluationTime);
    }

    /**
     * Return an {@link OpenPGPSignatureChain} from the given 3rd-party certificate to this certificate,
     * which represents a delegation of trust.
     * If no delegation signature is found, return null.
     *
     * @param thirdPartyCertificate {@link OpenPGPCertificate} of a 3rd party.
     * @return chain containing the latest delegation issued by the 3rd-party certificate
     */
    public OpenPGPSignatureChain getDelegationBy(OpenPGPCertificate thirdPartyCertificate)
    {
        return getDelegationBy(thirdPartyCertificate, new Date());
    }

    /**
     * Return an {@link OpenPGPSignatureChain} from the given 3rd-party certificate to this certificate,
     * which represents a delegation of trust at evaluation time.
     * If no delegation signature is found, return null.
     *
     * @param thirdPartyCertificate {@link OpenPGPCertificate} of a 3rd party.
     * @param evaluationTime        reference time
     * @return chain containing the (at evaluation time) latest delegation issued by the 3rd-party certificate
     */
    public OpenPGPSignatureChain getDelegationBy(
        OpenPGPCertificate thirdPartyCertificate,
        Date evaluationTime)
    {
        OpenPGPSignatureChains chainsBy = getPrimaryKey().
            getMergedDanglingExternalSignatureChainEndsFrom(thirdPartyCertificate, evaluationTime);
        return chainsBy.getCertificationAt(evaluationTime);
    }

    /**
     * Return an {@link OpenPGPSignatureChain} from the given 3rd-party certificate to this certificate,
     * which represents a revocation of trust.
     *
     * @param thirdPartyCertificate {@link OpenPGPCertificate} of a 3rd party.
     * @return chain containing the latest revocation issued by the 3rd party certificate
     */
    public OpenPGPSignatureChain getRevocationBy(OpenPGPCertificate thirdPartyCertificate)
    {
        return getRevocationBy(thirdPartyCertificate, new Date());
    }

    /**
     * Return an {@link OpenPGPSignatureChain} from the given 3rd-party certificate to this certificate,
     * which (at evaluation time) represents a revocation of trust.
     *
     * @param thirdPartyCertificate {@link OpenPGPCertificate} of a 3rd party.
     * @param evaluationTime        reference time
     * @return chain containing the (at evaluation time) latest revocation issued by the 3rd party certificate
     */
    public OpenPGPSignatureChain getRevocationBy(
        OpenPGPCertificate thirdPartyCertificate,
        Date evaluationTime)
    {
        OpenPGPSignatureChains chainsBy = getPrimaryKey()
            .getMergedDanglingExternalSignatureChainEndsFrom(thirdPartyCertificate, evaluationTime);
        return chainsBy.getRevocationAt(evaluationTime);
    }

    /**
     * Component on an OpenPGP certificate.
     * Components can either be {@link OpenPGPComponentKey keys} or {@link OpenPGPIdentityComponent identities}.
     */
    public static abstract class OpenPGPCertificateComponent
    {
        private final OpenPGPCertificate certificate;

        public OpenPGPCertificateComponent(OpenPGPCertificate certificate)
        {
            this.certificate = certificate;
        }

        /**
         * Return this components {@link OpenPGPCertificate}.
         *
         * @return certificate
         */
        public OpenPGPCertificate getCertificate()
        {
            return certificate;
        }

        /**
         * Return a detailed String representation of this component.
         *
         * @return detailed String representation
         */
        public abstract String toDetailString();

        /**
         * Return true, if the component is currently validly bound to the certificate.
         *
         * @return true if bound
         */
        public boolean isBound()
        {
            return isBoundAt(new Date());
        }

        /**
         * Return true, if this component is - at evaluation time - properly bound to its certificate.
         *
         * @param evaluationTime evaluation time
         * @return true if bound, false otherwise
         */
        public boolean isBoundAt(Date evaluationTime)
        {
            return getCertificate().isBound(this, evaluationTime);
        }

        /**
         * Return all {@link OpenPGPSignatureChains} that bind this component.
         *
         * @return signature chains
         */
        public OpenPGPSignatureChains getSignatureChains()
        {
            OpenPGPSignatureChains chains = getCertificate().getAllSignatureChainsFor(this);
            if (getPublicComponent() instanceof OpenPGPPrimaryKey)
            {
                OpenPGPPrimaryKey pk = (OpenPGPPrimaryKey)getPublicComponent();
                if (!pk.getUserIDs().isEmpty())
                {
                    chains.addAll(getCertificate().getAllSignatureChainsFor(pk.getUserIDs().get(0)));
                }
            }
            return chains;
        }

        /**
         * Return the (at evaluation time) latest certification signature binding this component.
         *
         * @param evaluationTime reference time
         * @return latest component certification signature
         */
        public OpenPGPComponentSignature getCertification(Date evaluationTime)
        {
            OpenPGPSignatureChain certification = getSignatureChains().getCertificationAt(evaluationTime);
            if (certification != null)
            {
                return certification.getSignature();
            }
            return null;
        }

        /**
         * Return the (at evaluation time) latest revocation signature revoking this component.
         *
         * @param evaluationTime reference time
         * @return latest component revocation signature
         */
        public OpenPGPComponentSignature getRevocation(Date evaluationTime)
        {
            OpenPGPSignatureChain revocation = getSignatureChains().getRevocationAt(evaluationTime);
            if (revocation != null)
            {
                return revocation.getSignature();
            }
            return null;
        }

        /**
         * Return the latest self-signature on the component.
         * That might either be a certification signature, or a revocation.
         *
         * @return latest self signature
         */
        public OpenPGPComponentSignature getLatestSelfSignature()
        {
            return getLatestSelfSignature(new Date());
        }

        /**
         * Return the (at evaluation time) latest self-signature on the component.
         * That might either be a certification signature, or a revocation.
         *
         * @param evaluationTime reference time
         * @return latest self signature
         */
        public abstract OpenPGPComponentSignature getLatestSelfSignature(Date evaluationTime);

        /**
         * Return the public {@link OpenPGPCertificateComponent} that belongs to this component.
         * For public components (pubkeys, identities...), that's simply this, while secret components
         * return their corresponding public component.
         * This is used to properly map secret key and public key components in {@link Map Maps} that use
         * {@link OpenPGPCertificateComponent components} as map keys.
         *
         * @return public certificate component
         */
        protected OpenPGPCertificateComponent getPublicComponent()
        {
            return this;
        }

        /**
         * Return the {@link OpenPGPComponentKey} belonging to this {@link OpenPGPCertificateComponent}.
         * If this {@link OpenPGPCertificateComponent} is an instance of {@link OpenPGPComponentKey},
         * the method simply returns <pre>this</pre>.
         * If instead, the {@link OpenPGPCertificateComponent} is an {@link OpenPGPIdentityComponent},
         * the primary key it is bound to is returned.
         *
         * @return {@link OpenPGPComponentKey} of this {@link OpenPGPCertificateComponent}.
         */
        protected abstract OpenPGPComponentKey getKeyComponent();

        /**
         * Return the {@link KeyFlags} signature subpacket that currently applies to the key.
         *
         * @return key flags subpacket
         */
        public KeyFlags getKeyFlags()
        {
            return getKeyFlags(new Date());
        }

        /**
         * Return the {@link KeyFlags} signature subpacket that - at evaluation time - applies to the key.
         *
         * @param evaluationTime evaluation time
         * @return key flags subpacket
         */
        public KeyFlags getKeyFlags(Date evaluationTime)
        {
            OpenPGPSignature.OpenPGPSignatureSubpacket subpacket = getApplyingSubpacket(
                evaluationTime, SignatureSubpacketTags.KEY_FLAGS);
            if (subpacket != null)
            {
                return (KeyFlags)subpacket.getSubpacket();
            }
            return null;
        }

        /**
         * Return <pre>true</pre>, if the key has any of the given key flags.
         * <p>
         * Note: To check if the key has EITHER flag A or B, call <pre>hasKeyFlags(evalTime, A, B)</pre>.
         * To instead check, if the key has BOTH flags A AND B, call <pre>hasKeyFlags(evalTime, A &amp; B)</pre>.
         *
         * @param evaluationTime evaluation time
         * @param flags          key flags (see {@link KeyFlags} for possible values)
         * @return true if the key has ANY of the provided flags
         */
        public boolean hasKeyFlags(Date evaluationTime, int... flags)
        {
            KeyFlags keyFlags = getKeyFlags(evaluationTime);
            if (keyFlags == null)
            {
                // Key has no key-flags
                return false;
            }

            // Check if key has the desired key-flags
            for (int i = 0; i < flags.length; ++i)
            {
                if (((keyFlags.getFlags() & flags[i]) == flags[i]))
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * Return the {@link Features} signature subpacket that currently applies to the key.
         *
         * @return feature signature subpacket
         */
        public Features getFeatures()
        {
            return getFeatures(new Date());
        }

        /**
         * Return the {@link Features} signature subpacket that - at evaluation time - applies to the key.
         *
         * @param evaluationTime evaluation time
         * @return features subpacket
         */
        public Features getFeatures(Date evaluationTime)
        {
            OpenPGPSignature.OpenPGPSignatureSubpacket subpacket = getApplyingSubpacket(evaluationTime, SignatureSubpacketTags.FEATURES);
            if (subpacket != null)
            {
                return (Features)subpacket.getSubpacket();
            }
            return null;
        }

        /**
         * Return the {@link PreferredAEADCiphersuites} that apply to this (sub-)key.
         * Note: This refers to AEAD preferences as defined in rfc9580, NOT LibrePGP AEAD algorithms.
         *
         * @return AEAD algorithm preferences
         */
        public PreferredAEADCiphersuites getAEADCipherSuitePreferences()
        {
            return getAEADCipherSuitePreferences(new Date());
        }

        /**
         * Return the {@link PreferredAEADCiphersuites} that - at evaluation time - apply to this (sub-)key.
         * Note: This refers to AEAD preferences as defined in rfc9580, NOT LibrePGP AEAD algorithms.
         *
         * @param evaluationTime evaluation time
         * @return AEAD algorithm preferences at evaluation time
         */
        public PreferredAEADCiphersuites getAEADCipherSuitePreferences(Date evaluationTime)
        {
            OpenPGPSignature.OpenPGPSignatureSubpacket subpacket = getApplyingSubpacket(evaluationTime,
                SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS);
            if (subpacket != null)
            {
                return (PreferredAEADCiphersuites)subpacket.getSubpacket();
            }
            return null;
        }

        /**
         * Return the current symmetric encryption algorithm preferences of this (sub-)key.
         *
         * @return current preferred symmetric-key algorithm preferences
         */
        public PreferredAlgorithms getSymmetricCipherPreferences()
        {
            return getSymmetricCipherPreferences(new Date());
        }

        /**
         * Return the symmetric encryption algorithm preferences of this (sub-)key at evaluation time.
         *
         * @param evaluationTime evaluation time
         * @return current preferred symmetric-key algorithm preferences
         */
        public PreferredAlgorithms getSymmetricCipherPreferences(Date evaluationTime)
        {
            OpenPGPSignature.OpenPGPSignatureSubpacket subpacket = getApplyingSubpacket(evaluationTime, SignatureSubpacketTags.PREFERRED_SYM_ALGS);
            if (subpacket != null)
            {
                return (PreferredAlgorithms)subpacket.getSubpacket();
            }
            return null;
        }

        /**
         * Return the current signature hash algorithm preferences of this (sub-)key.
         *
         * @return hash algorithm preferences
         */
        public PreferredAlgorithms getHashAlgorithmPreferences()
        {
            return getHashAlgorithmPreferences(new Date());
        }

        /**
         * Return the signature hash algorithm preferences of this (sub-)key at evaluation time.
         *
         * @param evaluationTime evaluation time
         * @return hash algorithm preferences
         */
        public PreferredAlgorithms getHashAlgorithmPreferences(Date evaluationTime)
        {
            OpenPGPSignature.OpenPGPSignatureSubpacket subpacket = getApplyingSubpacket(evaluationTime, SignatureSubpacketTags.PREFERRED_HASH_ALGS);
            if (subpacket != null)
            {
                return (PreferredAlgorithms)subpacket.getSubpacket();
            }
            return null;
        }

        /**
         * Return the compression algorithm preferences of this (sub-)key.
         *
         * @return compression algorithm preferences
         */
        public PreferredAlgorithms getCompressionAlgorithmPreferences()
        {
            return getCompressionAlgorithmPreferences(new Date());
        }

        /**
         * Return the compression algorithm preferences of this (sub-)key at evaluation time.
         *
         * @param evaluationTime reference time
         * @return compression algorithm preferences
         */
        public PreferredAlgorithms getCompressionAlgorithmPreferences(Date evaluationTime)
        {
            OpenPGPSignature.OpenPGPSignatureSubpacket subpacket = getApplyingSubpacket(evaluationTime, SignatureSubpacketTags.PREFERRED_COMP_ALGS);
            if (subpacket != null)
            {
                return (PreferredAlgorithms)subpacket.getSubpacket();
            }
            return null;
        }

        /**
         * Return the {@link Date}, at which the key expires.
         *
         * @return key expiration time
         */
        public Date getKeyExpirationDate()
        {
            return getKeyExpirationDateAt(new Date());
        }

        /**
         * Return the {@link Date}, at which the key - at evaluation time - expires.
         *
         * @param evaluationTime evaluation time
         * @return key expiration time
         */
        public Date getKeyExpirationDateAt(Date evaluationTime)
        {
            return getLatestSelfSignature(evaluationTime).getKeyExpirationTime();
        }

        /**
         * Return the {@link SignatureSubpacket} instance of the given subpacketType, which currently applies to
         * the key. Since subpackets from the Direct-Key signature apply to all subkeys of a certificate,
         * this method first inspects the signature that immediately applies to this key (e.g. a subkey-binding
         * signature), and - if the queried subpacket is found in there, returns that instance.
         * Otherwise, indirectly applying signatures (e.g. Direct-Key signatures) are queried.
         * That way, preferences from the direct-key signature are considered, but per-key overwrites take precedence.
         *
         * @param evaluationTime evaluation time
         * @param subpacketType  subpacket type that is being searched for
         * @return subpacket from directly or indirectly applying signature
         * @see <a href="https://openpgp.dev/book/adv/verification.html#attribute-shadowing">
         * OpenPGP for application developers - Attribute Shadowing</a>
         */
        protected OpenPGPSignature.OpenPGPSignatureSubpacket getApplyingSubpacket(Date evaluationTime, int subpacketType)
        {
            OpenPGPSignatureChain binding = getSignatureChains().getCertificationAt(evaluationTime);
            if (binding == null)
            {
                // is not bound
                return null;
            }

            // Check signatures
            try
            {
                if (!binding.isValid())
                {
                    // Binding is incorrect
                    return null;
                }
            }
            catch (PGPSignatureException e)
            {
                // Binding cannot be verified
                return null;
            }

            // find signature "closest to the key", e.g. subkey binding signature
            OpenPGPComponentSignature keySignature = binding.getSignature();

            PGPSignatureSubpacketVector hashedSubpackets = keySignature.getSignature().getHashedSubPackets();
            if (hashedSubpackets == null || !hashedSubpackets.hasSubpacket(subpacketType))
            {
                // If the subkey binding signature doesn't carry the desired subpacket,
                //  check direct-key or primary uid sig instead
                OpenPGPSignatureChain preferenceBinding = getCertificate().getPreferenceSignature(evaluationTime);
                if (preferenceBinding == null)
                {
                    // No direct-key / primary uid sig found -> No subpacket
                    return null;
                }
                keySignature = preferenceBinding.getSignature();
                hashedSubpackets = keySignature.getSignature().getHashedSubPackets();
            }
            // else -> attribute from DK sig is shadowed by SB sig

            // Extract subpacket from hashed area
            SignatureSubpacket subpacket = hashedSubpackets.getSubpacket(subpacketType);
            if (subpacket == null)
            {
                return null;
            }
            return OpenPGPSignature.OpenPGPSignatureSubpacket.hashed(subpacket, keySignature);
        }

        /**
         * Iterate over signatures issued over this component by the given 3rd-party certificate,
         * merge them with the (at evaluation time) valid self-certification chain and return the
         * results.
         *
         * @param thirdPartyCertificate certificate of a 3rd party
         * @param evaluationTime        reference time
         * @return all 3rd party signatures on this component, merged with their issuer chains
         */
        protected OpenPGPSignatureChains getMergedDanglingExternalSignatureChainEndsFrom(
            OpenPGPCertificate thirdPartyCertificate,
            Date evaluationTime)
        {
            OpenPGPSignatureChains chainsBy = new OpenPGPSignatureChains(this);

            OpenPGPSignatureChains allChains = getCertificate().getAllSignatureChainsFor(this)
                .getChainsAt(evaluationTime);
            for (Iterator<OpenPGPSignatureChain> it = allChains.iterator(); it.hasNext(); )
            {
                OpenPGPSignatureChain.Link rootLink = it.next().getRootLink();
                for (Iterator<OpenPGPComponentKey> it2 = thirdPartyCertificate.getKeys().iterator(); it2.hasNext(); )
                {
                    OpenPGPComponentKey issuerKey = it2.next();
                    if (KeyIdentifier.matches(
                        rootLink.getSignature().getKeyIdentifiers(),
                        issuerKey.getKeyIdentifier(),
                        true))
                    {
                        OpenPGPSignatureChain externalChain = issuerKey.getSignatureChains().getChainAt(evaluationTime);
                        externalChain = externalChain.plus(
                            new OpenPGPComponentSignature(rootLink.signature.getSignature(), issuerKey, this));
                        chainsBy.add(externalChain);
                    }
                }
            }
            return chainsBy;
        }
    }

    /**
     * OpenPGP Signature made over some {@link OpenPGPCertificateComponent} on a {@link OpenPGPCertificate}.
     */
    public static class OpenPGPComponentSignature
        extends OpenPGPSignature
    {

        private final OpenPGPCertificateComponent target;

        /**
         * Component signature.
         *
         * @param signature signature
         * @param issuer    key that issued the signature.
         *                  Is nullable (e.g. for 3rd party sigs where the certificate is not available).
         * @param target    signed certificate component
         */
        public OpenPGPComponentSignature(PGPSignature signature,
                                         OpenPGPComponentKey issuer,
                                         OpenPGPCertificateComponent target)
        {
            super(signature, issuer);
            this.target = target;
        }

        /**
         * Return the {@link OpenPGPComponentKey} that issued this signature.
         *
         * @return issuer
         */
        public OpenPGPComponentKey getIssuerComponent()
        {
            return getIssuer();
        }

        /**
         * Return the {@link OpenPGPCertificateComponent} that this signature was calculated over.
         *
         * @return target
         */
        public OpenPGPCertificateComponent getTargetComponent()
        {
            return target;
        }

        /**
         * Return the {@link OpenPGPComponentKey} that this signature is calculated over.
         * Contrary to {@link #getTargetComponent()}, which returns the actual target, this method returns the
         * {@link OpenPGPComponentKey} "closest" to the target.
         * For a subkey-binding signature, this is the target subkey, while for an identity-binding signature
         * (binding for a user-id or attribute) the return value is the {@link OpenPGPComponentKey} which
         * carries the identity.
         *
         * @return target key component of the signature
         */
        public OpenPGPComponentKey getTargetKeyComponent()
        {
            if (getTargetComponent() instanceof OpenPGPIdentityComponent)
            {
                // Identity signatures indirectly authenticate the primary key
                return ((OpenPGPIdentityComponent)getTargetComponent()).getPrimaryKey();
            }
            if (getTargetComponent() instanceof OpenPGPComponentKey)
            {
                // Key signatures authenticate the target key
                return (OpenPGPComponentKey)getTargetComponent();
            }
            throw new IllegalArgumentException("Unknown target type.");
        }

        /**
         * Return the key expiration time stored in the signature.
         *
         * @return key expiration time
         */
        public Date getKeyExpirationTime()
        {
            PGPSignatureSubpacketVector hashed = signature.getHashedSubPackets();
            if (hashed == null)
            {
                // v3 sigs have no expiration
                return null;
            }
            long exp = hashed.getKeyExpirationTime();
            if (exp < 0)
            {
                throw new RuntimeException("Negative key expiration time");
            }

            if (exp == 0L)
            {
                // Explicit or implicit no expiration
                return null;
            }

            return new Date(getTargetKeyComponent().getCreationTime().getTime() + 1000 * exp);
        }

        /**
         * Verify this signature.
         *
         * @param implementation OpenPGP implementation
         * @throws PGPSignatureException if the signature cannot be verified successfully
         */
        public void verify(OpenPGPImplementation implementation)
            throws PGPSignatureException
        {
            verify(implementation.pgpContentVerifierBuilderProvider(), implementation.policy());
        }

        /**
         * Verify this signature.
         *
         * @param contentVerifierBuilderProvider provider for verifiers
         * @param policy                         algorithm policy
         * @throws PGPSignatureException if the signature cannot be verified successfully
         */
        public void verify(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider,
                           OpenPGPPolicy policy)
            throws PGPSignatureException
        {
            if (issuer == null)
            {
                // No issuer available
                throw new MissingIssuerCertException(this, "Issuer certificate unavailable.");
            }

            sanitize(issuer, policy);

            // Direct-Key signature
            if (signature.getSignatureType() == PGPSignature.DIRECT_KEY
                || signature.getSignatureType() == PGPSignature.KEY_REVOCATION)
            {
                verifyKeySignature(
                    issuer,
                    target.getKeyComponent(),
                    contentVerifierBuilderProvider);
            }

            // Subkey binding signature
            else if (signature.getSignatureType() == PGPSignature.SUBKEY_BINDING)
            {
                // For signing-capable subkeys, check the embedded primary key binding signature
                verifyEmbeddedPrimaryKeyBinding(contentVerifierBuilderProvider, policy, getCreationTime());

                // Binding signature MUST NOT predate the subkey itself
                if (((OpenPGPSubkey)target).getCreationTime().after(signature.getCreationTime()))
                {
                    isCorrect = false;
                    throw new MalformedOpenPGPSignatureException(this, "Subkey binding signature predates subkey creation time.");
                }

                verifyKeySignature(
                    issuer,
                    (OpenPGPSubkey)target,
                    contentVerifierBuilderProvider);
            }

            else if (signature.getSignatureType() == PGPSignature.SUBKEY_REVOCATION)
            {
                // Binding signature MUST NOT predate the subkey itself
                if (((OpenPGPSubkey)target).getCreationTime().after(signature.getCreationTime()))
                {
                    isCorrect = false;
                    throw new MalformedOpenPGPSignatureException(this, "Subkey revocation signature predates subkey creation time.");
                }

                verifyKeySignature(
                    issuer,
                    (OpenPGPSubkey)target,
                    contentVerifierBuilderProvider);
            }

            // User-ID binding
            else if (target instanceof OpenPGPUserId)
            {
                verifyUserIdSignature(
                    issuer,
                    (OpenPGPUserId)target,
                    contentVerifierBuilderProvider);
            }

            // User-Attribute binding
            else if (target instanceof OpenPGPUserAttribute)
            {
                verifyUserAttributeSignature(
                    issuer,
                    (OpenPGPUserAttribute)target,
                    contentVerifierBuilderProvider);
            }

            else
            {
                throw new PGPSignatureException("Unexpected signature type: " + getType());
            }
        }

        /**
         * Verify a signature of type {@link PGPSignature#PRIMARYKEY_BINDING}, which is typically embedded as
         * {@link org.bouncycastle.bcpg.sig.EmbeddedSignature} inside a signature of type
         * {@link PGPSignature#SUBKEY_BINDING} for a signing capable subkey.
         *
         * @param contentVerifierBuilderProvider provider for content verifier builders
         * @param policy                         algorithm policy
         * @param signatureCreationTime          creation time of the signature
         * @throws PGPSignatureException if an exception happens during signature verification
         */
        private void verifyEmbeddedPrimaryKeyBinding(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider,
                                                     OpenPGPPolicy policy, Date signatureCreationTime)
            throws PGPSignatureException
        {
            int keyFlags = signature.getHashedSubPackets().getKeyFlags();
            if ((keyFlags & KeyFlags.SIGN_DATA) != KeyFlags.SIGN_DATA)
            {
                // Non-signing key - no embedded primary key binding sig required
                return;
            }

            OpenPGPComponentKey subkey = getTargetKeyComponent();
            // Signing subkey needs embedded primary key binding signature
            List<PGPSignature> embeddedSignatures = new ArrayList<PGPSignature>();
            try
            {
                PGPSignatureList sigList = signature.getHashedSubPackets().getEmbeddedSignatures();
                addSignatures(embeddedSignatures, sigList);
                sigList = signature.getUnhashedSubPackets().getEmbeddedSignatures();
                addSignatures(embeddedSignatures, sigList);
            }
            catch (PGPException e)
            {
                throw new PGPSignatureException("Cannot extract embedded signature.", e);
            }

            if (embeddedSignatures.isEmpty())
            {
                throw new MalformedOpenPGPSignatureException(
                    this,
                    "Signing key SubkeyBindingSignature MUST contain embedded PrimaryKeyBindingSignature.");
            }

            PGPSignatureException exception = null;
            for (Iterator<PGPSignature> it = embeddedSignatures.iterator(); it.hasNext(); )
            {
                PGPSignature primaryKeyBinding = it.next();
                OpenPGPCertificate.OpenPGPComponentSignature backSig =
                    new OpenPGPCertificate.OpenPGPComponentSignature(
                        primaryKeyBinding,
                        subkey,
                        issuer);

                if (primaryKeyBinding.getSignatureType() != PGPSignature.PRIMARYKEY_BINDING)
                {
                    exception = new PGPSignatureException("Unexpected embedded signature type: " + primaryKeyBinding.getSignatureType());
                    continue;
                }

                if (!backSig.isEffectiveAt(signatureCreationTime))
                {
                    exception = new PGPSignatureException("Embedded PrimaryKeyBinding signature is expired or not yet effective.");
                    continue;
                }

                try
                {
                    backSig.sanitize(subkey, policy);

                    // needs to be called last to prevent false positives
                    backSig.verifyKeySignature(subkey, issuer, contentVerifierBuilderProvider);

                    // valid -> return successfully
                    return;
                }
                catch (PGPSignatureException e)
                {
                    exception = e;
                }
            }

            // if we end up here, it means we have only found invalid sigs
            throw exception;
        }

        private static void addSignatures(List<PGPSignature> embeddedSignatures, PGPSignatureList sigList)
        {
            for (Iterator<PGPSignature> it = sigList.iterator(); it.hasNext(); )
            {
                embeddedSignatures.add(it.next());
            }
        }

        /**
         * Verify a signature of type {@link PGPSignature#DIRECT_KEY}, {@link PGPSignature#KEY_REVOCATION},
         * {@link PGPSignature#SUBKEY_BINDING} or {@link PGPSignature#SUBKEY_REVOCATION}.
         *
         * @param issuer                         issuing component key
         * @param target                         targeted component key
         * @param contentVerifierBuilderProvider provider for content verifier builders
         * @throws PGPSignatureException if an exception happens during signature verification
         */
        protected void verifyKeySignature(
            OpenPGPComponentKey issuer,
            OpenPGPComponentKey target,
            PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
            throws PGPSignatureException
        {
            this.isTested = true;
            try
            {
                signature.init(contentVerifierBuilderProvider, issuer.getPGPPublicKey());
                if (signature.getSignatureType() == PGPSignature.DIRECT_KEY
                    || signature.getSignatureType() == PGPSignature.KEY_REVOCATION)
                {
                    // Direct-Key Signature
                    isCorrect = signature.verifyCertification(target.getPGPPublicKey());
                }
                else if (signature.getSignatureType() == PGPSignature.PRIMARYKEY_BINDING)
                {
                    isCorrect = signature.verifyCertification(target.getPGPPublicKey(), issuer.getPGPPublicKey());
                }
                else
                {
                    // Subkey Binding Signature
                    isCorrect = signature.verifyCertification(issuer.getPGPPublicKey(), target.getPGPPublicKey());
                }

                if (!isCorrect)
                {
                    throw new IncorrectOpenPGPSignatureException(this, "Key Signature is not correct.");
                }
            }
            catch (PGPException e)
            {
                this.isCorrect = false;
                throw new PGPSignatureException("Key Signature could not be verified.", e);
            }
            catch (ClassCastException e)
            {
                this.isCorrect = false;
                throw new PGPSignatureException("Key Signature could not be verified.", e);
            }
        }

        /**
         * Verify a certification signature over an {@link OpenPGPUserId}.
         * The signature is of type {@link PGPSignature#DEFAULT_CERTIFICATION}, {@link PGPSignature#NO_CERTIFICATION},
         * {@link PGPSignature#CASUAL_CERTIFICATION}, {@link PGPSignature#POSITIVE_CERTIFICATION} or
         * {@link PGPSignature#CERTIFICATION_REVOCATION}.
         *
         * @param issuer                         issuing component key
         * @param target                         targeted userid
         * @param contentVerifierBuilderProvider provider for content verifier builders
         * @throws PGPSignatureException if an exception happens during signature verification
         */
        protected void verifyUserIdSignature(OpenPGPComponentKey issuer,
                                             OpenPGPUserId target,
                                             PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
            throws PGPSignatureException
        {
            this.isTested = true;
            try
            {
                signature.init(contentVerifierBuilderProvider, issuer.getPGPPublicKey());
                isCorrect = signature.verifyCertification(target.getUserId(), target.getPrimaryKey().getPGPPublicKey());
                if (!isCorrect)
                {
                    throw new IncorrectOpenPGPSignatureException(this, "UserID Signature is not correct.");
                }
            }
            catch (PGPException e)
            {
                this.isCorrect = false;
                throw new PGPSignatureException("UserID Signature could not be verified.", e);
            }
            catch (ClassCastException e)
            {
                this.isCorrect = false;
                throw new PGPSignatureException("UserID Signature could not be verified.", e);
            }
        }

        /**
         * Verify a certification signature over an {@link OpenPGPUserAttribute}.
         * The signature is of type {@link PGPSignature#DEFAULT_CERTIFICATION}, {@link PGPSignature#NO_CERTIFICATION},
         * {@link PGPSignature#CASUAL_CERTIFICATION}, {@link PGPSignature#POSITIVE_CERTIFICATION} or
         * {@link PGPSignature#CERTIFICATION_REVOCATION}.
         *
         * @param issuer                         issuing component key
         * @param target                         targeted userid
         * @param contentVerifierBuilderProvider provider for content verifier builders
         * @throws PGPSignatureException if an exception happens during signature verification
         */
        protected void verifyUserAttributeSignature(OpenPGPComponentKey issuer,
                                                    OpenPGPUserAttribute target,
                                                    PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
            throws PGPSignatureException
        {
            this.isTested = true;
            try
            {
                signature.init(contentVerifierBuilderProvider, issuer.getPGPPublicKey());
                isCorrect = signature.verifyCertification(target.getUserAttribute(), target.getPrimaryKey().getPGPPublicKey());
                if (!isCorrect)
                {
                    throw new IncorrectOpenPGPSignatureException(this, "UserAttribute Signature is not correct.");
                }
            }
            catch (PGPException e)
            {
                this.isCorrect = false;
                throw new PGPSignatureException("Could not verify UserAttribute Signature.", e);
            }
            catch (ClassCastException e)
            {
                this.isCorrect = false;
                throw new PGPSignatureException("Could not verify UserAttribute Signature.", e);
            }
        }

        @Override
        protected String getTargetDisplay()
        {
            return target.toString();
        }
    }

    /**
     * A component key is either an {@link OpenPGPPrimaryKey}, or an {@link OpenPGPSubkey}.
     *
     * @see <a href="https://openpgp.dev/book/certificates.html#layers-of-keys-in-openpgp">
     * OpenPGP for Application Developers - Layers of keys in OpenPGP</a>
     */
    public static abstract class OpenPGPComponentKey
        extends OpenPGPCertificateComponent
    {
        protected final PGPPublicKey rawPubkey;

        /**
         * Constructor.
         *
         * @param rawPubkey   public key
         * @param certificate certificate
         */
        public OpenPGPComponentKey(PGPPublicKey rawPubkey, OpenPGPCertificate certificate)
        {
            super(certificate);
            this.rawPubkey = rawPubkey;
        }

        /**
         * Return the underlying {@link PGPPublicKey} of this {@link OpenPGPComponentKey}.
         *
         * @return public key
         */
        public PGPPublicKey getPGPPublicKey()
        {
            return rawPubkey;
        }

        /**
         * Return the {@link KeyIdentifier} of this key.
         *
         * @return key identifier
         */
        public KeyIdentifier getKeyIdentifier()
        {
            return rawPubkey.getKeyIdentifier();
        }

        /**
         * Return the public key algorithm.
         *
         * @return public key algorithm id
         * @see org.bouncycastle.bcpg.PublicKeyAlgorithmTags
         */
        public int getAlgorithm()
        {
            return getPGPPublicKey().getAlgorithm();
        }

        /**
         * Return the public key version.
         *
         * @return key version
         */
        public int getVersion()
        {
            return getPGPPublicKey().getVersion();
        }

        /**
         * Return the creation time of this key.
         *
         * @return creation time
         */
        public Date getCreationTime()
        {
            return rawPubkey.getCreationTime();
        }

        /**
         * Return true, if this {@link OpenPGPComponentKey} represents the primary key of an {@link OpenPGPCertificate}.
         *
         * @return true if primary, false if subkey
         */
        public abstract boolean isPrimaryKey();

        @Override
        public OpenPGPComponentSignature getLatestSelfSignature(Date evaluationTime)
        {
            OpenPGPSignatureChain currentDKChain = getSignatureChains().getChainAt(evaluationTime);
            if (currentDKChain != null && !currentDKChain.chainLinks.isEmpty())
            {
                return currentDKChain.getSignature();
            }
            return null;
        }

        /**
         * Return true, if the key is currently marked as encryption key.
         *
         * @return true if the key is an encryption key, false otherwise
         */
        public boolean isEncryptionKey()
        {
            return isEncryptionKey(new Date());
        }

        /**
         * Return true, if the is - at evaluation time - marked as an encryption key.
         *
         * @param evaluationTime evaluation time
         * @return true if key is an encryption key at evaluation time, false otherwise
         */
        public boolean isEncryptionKey(Date evaluationTime)
        {
            if (!rawPubkey.isEncryptionKey())
            {
                // Skip keys that are not encryption-capable by algorithm
                return false;
            }

            return hasKeyFlags(evaluationTime, KeyFlags.ENCRYPT_STORAGE) ||
                hasKeyFlags(evaluationTime, KeyFlags.ENCRYPT_COMMS);
        }

        /**
         * Return true, if the key is currently marked as a signing key for message signing.
         *
         * @return true, if key is currently signing key
         */
        public boolean isSigningKey()
        {
            return isSigningKey(new Date());
        }

        /**
         * Return true, if the key is - at evaluation time - marked as signing key for message signing.
         *
         * @param evaluationTime evaluation time
         * @return true if key is signing key at evaluation time
         */
        public boolean isSigningKey(Date evaluationTime)
        {
            if (!PublicKeyUtils.isSigningAlgorithm(rawPubkey.getAlgorithm()))
            {
                // Key is not signing-capable by algorithm
                return false;
            }

            return hasKeyFlags(evaluationTime, KeyFlags.SIGN_DATA);
        }

        /**
         * Return true, if the key is currently marked as certification key that can sign 3rd-party certificates.
         *
         * @return true, if key is certification key
         */
        public boolean isCertificationKey()
        {
            return isCertificationKey(new Date());
        }

        /**
         * Return true, if the key is - at evaluation time - marked as certification key that can sign 3rd-party
         * certificates.
         *
         * @param evaluationTime evaluation time
         * @return true if key is certification key at evaluation time
         */
        public boolean isCertificationKey(Date evaluationTime)
        {
            if (!PublicKeyUtils.isSigningAlgorithm(rawPubkey.getAlgorithm()))
            {
                // Key is not signing-capable by algorithm
                return false;
            }

            return hasKeyFlags(evaluationTime, KeyFlags.CERTIFY_OTHER);
        }

        @Override
        protected OpenPGPComponentKey getKeyComponent()
        {
            // This already IS a component key
            return this;
        }

        @Override
        public int hashCode()
        {
            return getPGPPublicKey().hashCode();
        }

        @Override
        public boolean equals(Object obj)
        {
            if (obj == null)
            {
                return false;
            }
            if (this == obj)
            {
                return true;
            }
            if (!(obj instanceof OpenPGPComponentKey))
            {
                return false;
            }
            OpenPGPComponentKey other = (OpenPGPComponentKey)obj;
            return getPGPPublicKey().equals(other.getPGPPublicKey());
        }
    }

    /**
     * The primary key of a {@link OpenPGPCertificate}.
     */
    public static class OpenPGPPrimaryKey
        extends OpenPGPComponentKey
    {
        @Override
        public String toString()
        {
            return "PrimaryKey[" + Long.toHexString(getKeyIdentifier().getKeyId()).toUpperCase(Locale.getDefault()) + "]";
        }

        @Override
        public String toDetailString()
        {
            return "PrimaryKey[" + getKeyIdentifier() + "] (" + UTCUtil.format(getCreationTime()) + ")";
        }

        protected final List<OpenPGPIdentityComponent> identityComponents;

        public OpenPGPPrimaryKey(PGPPublicKey rawPubkey, OpenPGPCertificate certificate)
        {
            super(rawPubkey, certificate);
            this.identityComponents = new ArrayList<OpenPGPIdentityComponent>();

            Iterator<String> userIds = rawPubkey.getUserIDs();
            while (userIds.hasNext())
            {
                identityComponents.add(new OpenPGPUserId(userIds.next(), this));
            }

            Iterator<PGPUserAttributeSubpacketVector> userAttributes = rawPubkey.getUserAttributes();
            while (userAttributes.hasNext())
            {
                identityComponents.add(new OpenPGPUserAttribute(userAttributes.next(), this));
            }
        }

        @Override
        public boolean isPrimaryKey()
        {
            return true;
        }

        /**
         * Return the latest DirectKey self-signature on this primary key.
         *
         * @return latest direct key self-signature.
         */
        public OpenPGPComponentSignature getLatestDirectKeySelfSignature()
        {
            return getLatestDirectKeySelfSignature(new Date());
        }

        /**
         * Return the (at evaluation time) latest DirectKey self-signature on this primary key.
         *
         * @param evaluationTime reference time
         * @return latest (at evaluation time) direct key self-signature
         */
        public OpenPGPComponentSignature getLatestDirectKeySelfSignature(Date evaluationTime)
        {
            OpenPGPSignatureChain currentDKChain = getCertificate().getAllSignatureChainsFor(this)
                .getCertificationAt(evaluationTime);
            if (currentDKChain != null && !currentDKChain.chainLinks.isEmpty())
            {
                return currentDKChain.getSignature();
            }

            return null;
        }

        /**
         * Return the latest KeyRevocation self-signature on this primary key.
         *
         * @return latest key revocation self-signature
         */
        public OpenPGPComponentSignature getLatestKeyRevocationSelfSignature()
        {
            return getLatestKeyRevocationSelfSignature(new Date());
        }

        /**
         * Return the (at evaluation time) latest KeyRevocation self-signature on this primary key.
         *
         * @param evaluationTime reference time
         * @return latest (at evaluation time) key revocation self-signature
         */
        public OpenPGPComponentSignature getLatestKeyRevocationSelfSignature(Date evaluationTime)
        {
            OpenPGPSignatureChain currentRevocationChain = getCertificate().getAllSignatureChainsFor(this)
                .getRevocationAt(evaluationTime);
            if (currentRevocationChain != null && !currentRevocationChain.chainLinks.isEmpty())
            {
                return currentRevocationChain.getSignature();
            }
            return null;
        }

        @Override
        public OpenPGPComponentSignature getLatestSelfSignature(Date evaluationTime)
        {
            List<OpenPGPComponentSignature> signatures = new ArrayList<OpenPGPComponentSignature>();

            OpenPGPComponentSignature directKeySig = getLatestDirectKeySelfSignature(evaluationTime);
            if (directKeySig != null)
            {
                signatures.add(directKeySig);
            }

            OpenPGPComponentSignature keyRevocation = getLatestKeyRevocationSelfSignature(evaluationTime);
            if (keyRevocation != null)
            {
                signatures.add(keyRevocation);
            }

            for (Iterator<OpenPGPIdentityComponent> it = getCertificate().getIdentities().iterator(); it.hasNext(); )
            {
                OpenPGPComponentSignature identitySig = it.next().getLatestSelfSignature(evaluationTime);
                if (identitySig != null)
                {
                    signatures.add(identitySig);
                }
            }

            OpenPGPComponentSignature latest = null;
            for (Iterator<OpenPGPComponentSignature> it = signatures.iterator(); it.hasNext(); )
            {
                OpenPGPComponentSignature signature = it.next();
                if (latest == null || signature.getCreationTime().after(latest.getCreationTime()))
                {
                    latest = signature;
                }
            }
            return latest;
        }

        /**
         * Return all {@link OpenPGPUserId OpenPGPUserIds} on this key.
         *
         * @return user ids
         */
        public List<OpenPGPUserId> getUserIDs()
        {
            List<OpenPGPUserId> userIds = new ArrayList<OpenPGPUserId>();
            for (Iterator<OpenPGPIdentityComponent> it = identityComponents.iterator(); it.hasNext(); )
            {
                OpenPGPIdentityComponent identity = it.next();
                if (identity instanceof OpenPGPUserId)
                {
                    userIds.add((OpenPGPUserId)identity);
                }
            }
            return userIds;
        }

        /**
         * Return a {@link List} containing all currently valid {@link OpenPGPUserId OpenPGPUserIds} on this
         * primary key.
         *
         * @return valid userids
         */
        public List<OpenPGPUserId> getValidUserIds()
        {
            return getValidUserIDs(new Date());
        }

        /**
         * Return a {@link List} containing all valid (at evaluation time) {@link OpenPGPUserId OpenPGPUserIds}
         * on this primary key.
         *
         * @param evaluationTime reference time
         * @return valid (at evaluation time) userids
         */
        public List<OpenPGPUserId> getValidUserIDs(Date evaluationTime)
        {
            List<OpenPGPUserId> userIds = new ArrayList<OpenPGPUserId>();
            for (Iterator<OpenPGPIdentityComponent> it = identityComponents.iterator(); it.hasNext(); )
            {
                OpenPGPIdentityComponent identity = it.next();
                if (identity instanceof OpenPGPUserId && identity.isBoundAt(evaluationTime))
                {
                    userIds.add((OpenPGPUserId)identity);
                }
            }
            return userIds;
        }

        /**
         * Return the {@link OpenPGPUserId}, which is - at evaluation time - explicitly marked as primary.
         *
         * @param evaluationTime evaluation time
         * @return explicit primary userid
         */
        public OpenPGPUserId getExplicitPrimaryUserId(Date evaluationTime)
        {
            // Return the latest, valid, explicitly marked as primary UserID
            OpenPGPSignature latestBinding = null;
            OpenPGPUserId latestUid = null;

            for (Iterator<OpenPGPUserId> it = getUserIDs().iterator(); it.hasNext(); )
            {
                OpenPGPUserId userId = it.next();
                OpenPGPSignature.OpenPGPSignatureSubpacket subpacket =
                    userId.getApplyingSubpacket(evaluationTime, SignatureSubpacketTags.PRIMARY_USER_ID);
                if (subpacket == null)
                {
                    // Not bound at this time, or not explicit
                    continue;
                }

                PrimaryUserID primaryUserId = (PrimaryUserID)subpacket.getSubpacket();
                if (!primaryUserId.isPrimaryUserID())
                {
                    // explicitly marked as not primary
                    continue;
                }

                if (latestBinding == null ||
                    subpacket.getSignature().getCreationTime().after(latestBinding.getCreationTime()))
                {
                    latestBinding = subpacket.getSignature();
                    latestUid = userId;
                }
            }
            return latestUid;
        }

        /**
         * Return the {@link OpenPGPUserId}, which is - at evaluation time - considered primary,
         * either because it is explicitly marked as primary userid, or because it is implicitly primary
         * (e.g. because it is the sole user-id on the key).
         *
         * @param evaluationTime evaluation time
         * @return primary user-id
         */
        public OpenPGPUserId getExplicitOrImplicitPrimaryUserId(Date evaluationTime)
        {
            OpenPGPUserId explicitPrimaryUserId = getExplicitPrimaryUserId(evaluationTime);
            if (explicitPrimaryUserId != null)
            {
                return explicitPrimaryUserId;
            }

            // If no explicitly marked, valid primary UserID is found, return the oldest, valid UserId instead.
            OpenPGPSignature oldestBinding = null;
            OpenPGPUserId oldestUid = null;

            for (Iterator<OpenPGPUserId> it = getUserIDs().iterator(); it.hasNext(); )
            {
                OpenPGPUserId userId = it.next();
                OpenPGPSignatureChain chain = userId.getSignatureChains()
                    .getCertificationAt(evaluationTime);
                if (chain == null)
                {
                    // Not valid at this time
                    continue;
                }

                OpenPGPSignature binding = chain.getSignature();
                if (oldestBinding == null ||
                    binding.getCreationTime().before(oldestBinding.getCreationTime()))
                {
                    oldestBinding = binding;
                    oldestUid = userId;
                }
            }
            return oldestUid;
        }

        /**
         * Return all {@link OpenPGPUserAttribute OpenPGPUserAttributes} on this key.
         *
         * @return user attributes
         */
        public List<OpenPGPUserAttribute> getUserAttributes()
        {
            List<OpenPGPUserAttribute> userAttributes = new ArrayList<OpenPGPUserAttribute>();
            for (Iterator<OpenPGPIdentityComponent> it = identityComponents.iterator(); it.hasNext(); )
            {
                OpenPGPIdentityComponent identity = it.next();
                if (identity instanceof OpenPGPUserAttribute)
                {
                    userAttributes.add((OpenPGPUserAttribute)identity);
                }
            }
            return userAttributes;
        }

        /**
         * Return all direct-key and key-revocation signatures on the primary key.
         *
         * @return key signatures
         */
        protected List<OpenPGPComponentSignature> getKeySignatures()
        {
            Iterator<PGPSignature> iterator = rawPubkey.getSignatures();
            List<OpenPGPCertificate.OpenPGPComponentSignature> list = new ArrayList<OpenPGPCertificate.OpenPGPComponentSignature>();
            while (iterator.hasNext())
            {
                PGPSignature sig = iterator.next();
                int type = sig.getSignatureType();
                if (type != PGPSignature.DIRECT_KEY && type != PGPSignature.KEY_REVOCATION)
                {
                    continue;
                }
                // try to find issuer for self-signature
                OpenPGPCertificate.OpenPGPComponentKey issuer = getCertificate()
                    .getSigningKeyFor(sig);

                list.add(new OpenPGPCertificate.OpenPGPComponentSignature(sig, issuer, this));
            }
            return list;
        }

        /**
         * Return all signatures on the given {@link OpenPGPUserId}.
         *
         * @param identity user-id
         * @return list of user-id signatures
         */
        protected List<OpenPGPComponentSignature> getUserIdSignatures(OpenPGPUserId identity)
        {
            Iterator<PGPSignature> iterator = rawPubkey.getSignaturesForID(identity.getUserId());
            return signIterToList(identity, iterator);
        }

        /**
         * Return all signatures on the given {@link OpenPGPUserAttribute}.
         *
         * @param identity user-attribute
         * @return list of user-attribute signatures
         */
        protected List<OpenPGPComponentSignature> getUserAttributeSignatures(OpenPGPUserAttribute identity)
        {
            Iterator<PGPSignature> iterator = rawPubkey.getSignaturesForUserAttribute(identity.getUserAttribute());
            return signIterToList(identity, iterator);
        }

        private List<OpenPGPComponentSignature> signIterToList(OpenPGPIdentityComponent identity, Iterator<PGPSignature> iterator)
        {
            List<OpenPGPComponentSignature> list = new ArrayList<OpenPGPComponentSignature>();
            while (iterator.hasNext())
            {
                PGPSignature sig = iterator.next();
                // try to find issuer for self-signature
                OpenPGPComponentKey issuer = getCertificate()
                    .getSigningKeyFor(sig);

                list.add(new OpenPGPComponentSignature(sig, issuer, identity));
            }
            return list;
        }
    }

    /**
     * A subkey on a {@link OpenPGPCertificate}.
     */
    public static class OpenPGPSubkey
        extends OpenPGPComponentKey
    {
        public OpenPGPSubkey(PGPPublicKey rawPubkey, OpenPGPCertificate certificate)
        {
            super(rawPubkey, certificate);
        }

        @Override
        public boolean isPrimaryKey()
        {
            return false;
        }

        @Override
        public String toString()
        {
            return "Subkey[" + Long.toHexString(getKeyIdentifier().getKeyId()).toUpperCase(Locale.getDefault()) + "]";
        }

        @Override
        public String toDetailString()
        {
            return "Subkey[" + getKeyIdentifier() + "] (" + UTCUtil.format(getCreationTime()) + ")";
        }

        /**
         * Return all subkey-binding and -revocation signatures on the subkey.
         *
         * @return subkey signatures
         */
        protected List<OpenPGPComponentSignature> getKeySignatures()
        {
            Iterator<PGPSignature> iterator = rawPubkey.getSignatures();
            List<OpenPGPCertificate.OpenPGPComponentSignature> list = new ArrayList<OpenPGPCertificate.OpenPGPComponentSignature>();
            while (iterator.hasNext())
            {
                PGPSignature sig = iterator.next();
                int type = sig.getSignatureType();
                if (type != PGPSignature.SUBKEY_BINDING && type != PGPSignature.SUBKEY_REVOCATION)
                {
                    continue;
                }
                // try to find issuer for self-signature
                OpenPGPCertificate.OpenPGPComponentKey issuer = getCertificate()
                    .getSigningKeyFor(sig);

                list.add(new OpenPGPCertificate.OpenPGPComponentSignature(sig, issuer, this));
            }
            return list;
        }
    }

    /**
     * An identity bound to the {@link OpenPGPPrimaryKey} of a {@link OpenPGPCertificate}.
     * An identity may either be a {@link OpenPGPUserId} or (deprecated) {@link OpenPGPUserAttribute}.
     */
    public static abstract class OpenPGPIdentityComponent
        extends OpenPGPCertificateComponent
    {
        private final OpenPGPPrimaryKey primaryKey;

        public OpenPGPIdentityComponent(OpenPGPPrimaryKey primaryKey)
        {
            super(primaryKey.getCertificate());
            this.primaryKey = primaryKey;
        }

        /**
         * Return the primary key, which this identity belongs to.
         *
         * @return primary key
         */
        public OpenPGPPrimaryKey getPrimaryKey()
        {
            return primaryKey;
        }

        @Override
        public OpenPGPComponentSignature getLatestSelfSignature(Date evaluationTime)
        {
            OpenPGPSignatureChain currentChain = getSignatureChains().getChainAt(evaluationTime);
            if (currentChain != null && !currentChain.chainLinks.isEmpty())
            {
                return currentChain.getSignature();
            }
            return null;
        }

        @Override
        protected OpenPGPComponentKey getKeyComponent()
        {
            return primaryKey;
        }

        /**
         * Return the latest {@link OpenPGPSignatureChain} containing a certification issued by the given
         * 3rd-party certificate over this identity component.
         *
         * @param thirdPartyCertificate certificate of a 3rd party
         * @return 3rd party certification
         */
        public OpenPGPSignatureChain getCertificationBy(OpenPGPCertificate thirdPartyCertificate)
        {
            return getCertificationBy(thirdPartyCertificate, new Date());
        }

        /**
         * Return the latest (at evaluation time) {@link OpenPGPSignatureChain} containing a certification
         * issued by the given 3rd-party certificate over this identity component.
         *
         * @param evaluationTime        reference time
         * @param thirdPartyCertificate certificate of a 3rd party
         * @return 3rd party certification
         */
        public OpenPGPSignatureChain getCertificationBy(
            OpenPGPCertificate thirdPartyCertificate,
            Date evaluationTime)
        {
            OpenPGPSignatureChains chainsBy = getMergedDanglingExternalSignatureChainEndsFrom(thirdPartyCertificate, evaluationTime);
            return chainsBy.getCertificationAt(evaluationTime);
        }

        /**
         * Return the latest {@link OpenPGPSignatureChain} containing a revocation issued by the given
         * 3rd-party certificate over this identity component.
         *
         * @param thirdPartyCertificate certificate of a 3rd party
         * @return 3rd party revocation signature
         */
        public OpenPGPSignatureChain getRevocationBy(OpenPGPCertificate thirdPartyCertificate)
        {
            return getRevocationBy(thirdPartyCertificate, new Date());
        }

        /**
         * Return the latest (at evaluation time) {@link OpenPGPSignatureChain} containing a revocation issued by the given
         * 3rd-party certificate over this identity component.
         *
         * @param thirdPartyCertificate certificate of a 3rd party
         * @param evaluationTime        reference time
         * @return 3rd party revocation signature
         */
        public OpenPGPSignatureChain getRevocationBy(
            OpenPGPCertificate thirdPartyCertificate,
            Date evaluationTime)
        {
            OpenPGPSignatureChains chainsBy = getMergedDanglingExternalSignatureChainEndsFrom(thirdPartyCertificate, evaluationTime);
            return chainsBy.getRevocationAt(evaluationTime);
        }

        @Override
        public String toDetailString()
        {
            return toString();
        }
    }

    /**
     * A UserId.
     */
    public static class OpenPGPUserId
        extends OpenPGPIdentityComponent
    {
        private final String userId;

        public OpenPGPUserId(String userId, OpenPGPPrimaryKey primaryKey)
        {
            super(primaryKey);
            this.userId = userId;
        }

        /**
         * Return the {@link String} representation of the {@link OpenPGPUserId}.
         *
         * @return user-id
         */
        public String getUserId()
        {
            return userId;
        }

        @Override
        public String toString()
        {
            return "UserID[" + userId + "]";
        }

        @Override
        public boolean equals(Object obj)
        {
            if (obj == null)
            {
                return false;
            }
            if (this == obj)
            {
                return true;
            }
            if (!(obj instanceof OpenPGPUserId))
            {
                return false;
            }
            return getUserId().equals(((OpenPGPUserId)obj).getUserId());
        }

        @Override
        public int hashCode()
        {
            return userId.hashCode();
        }
    }

    /**
     * A UserAttribute.
     * Use of UserAttributes is deprecated in RFC9580.
     */
    public static class OpenPGPUserAttribute
        extends OpenPGPIdentityComponent
    {

        private final PGPUserAttributeSubpacketVector userAttribute;

        public OpenPGPUserAttribute(PGPUserAttributeSubpacketVector userAttribute, OpenPGPPrimaryKey primaryKey)
        {
            super(primaryKey);
            this.userAttribute = userAttribute;
        }

        /**
         * Return the underlying {@link PGPUserAttributeSubpacketVector} representing this {@link OpenPGPUserAttribute}.
         *
         * @return user attribute subpacket vector
         */
        public PGPUserAttributeSubpacketVector getUserAttribute()
        {
            return userAttribute;
        }

        @Override
        public String toString()
        {
            return "UserAttribute" + userAttribute.toString();
        }
    }

    /**
     * Chain of {@link OpenPGPSignature signatures}.
     * Such a chain originates from a certificates primary key and points towards some certificate component that
     * is bound to the certificate.
     * As for example a subkey can only be bound by a primary key that holds either at least one
     * direct-key self-signature or at least one user-id binding signature, multiple signatures may form
     * a validity chain.
     * An {@link OpenPGPSignatureChain} can either be a certification
     * ({@link #isCertification()}), e.g. it represents a positive binding,
     * or it can be a revocation ({@link #isRevocation()}) which invalidates a positive binding.
     */
    public static class OpenPGPSignatureChain
        implements Comparable<OpenPGPSignatureChain>, Iterable<OpenPGPSignatureChain.Link>
    {
        private final List<Link> chainLinks = new ArrayList<Link>();

        private OpenPGPSignatureChain(Link rootLink)
        {
            this.chainLinks.add(rootLink);
        }

        private OpenPGPSignatureChain(List<Link> links)
        {
            this.chainLinks.addAll(links);
        }

        // copy constructor
        private OpenPGPSignatureChain(OpenPGPSignatureChain copy)
        {
            this(copy.chainLinks);
        }

        /**
         * Return the signature from the leaf of the chain, which directly applies to the
         * {@link OpenPGPCertificateComponent}.
         *
         * @return signature
         */
        public OpenPGPComponentSignature getSignature()
        {
            return getLeafLink().getSignature();
        }

        /**
         * Return the first revocation signature in the chain, or null if the chain does not contain any revocations.
         *
         * @return first revocation signature
         */
        public OpenPGPComponentSignature getRevocation()
        {
            for (OpenPGPComponentSignature signature : getSignatures())
            {
                if (signature.isRevocation())
                {
                    return signature;
                }
            }
            return null;
        }

        /**
         * Return a List of all signatures in the chain.
         *
         * @return list of signatures
         */
        public List<OpenPGPComponentSignature> getSignatures()
        {
            List<OpenPGPComponentSignature> signatures = new ArrayList<OpenPGPComponentSignature>();
            for (Link link : chainLinks)
            {
                signatures.add(link.getSignature());
            }
            return signatures;
        }

        /**
         * Return an NEW instance of the {@link OpenPGPSignatureChain} with the new link appended.
         *
         * @param sig signature
         * @return new instance
         */
        public OpenPGPSignatureChain plus(OpenPGPComponentSignature sig)
        {
            if (getLeafLinkTargetKey() != sig.getIssuerComponent())
            {
                throw new IllegalArgumentException("Chain head is not equal to link issuer.");
            }

            OpenPGPSignatureChain chain = new OpenPGPSignatureChain(this);

            chain.chainLinks.add(Link.create(sig));

            return chain;
        }

        /**
         * Factory method for creating an {@link OpenPGPSignatureChain} with only a single link.
         *
         * @param sig signature
         * @return chain
         */
        public static OpenPGPSignatureChain direct(OpenPGPComponentSignature sig)
        {
            return new OpenPGPSignatureChain(Link.create(sig));
        }

        /**
         * Return the very first link in the chain.
         * This is typically a link that originates from the issuing certificates primary key.
         *
         * @return root link
         */
        public Link getRootLink()
        {
            return chainLinks.get(0);
        }

        /**
         * Return the issuer of the root link. This is typically the issuing certificates primary key.
         *
         * @return root links issuer
         */
        public OpenPGPComponentKey getRootLinkIssuer()
        {
            return getRootLink().getSignature().getIssuer();
        }

        /**
         * Return the last link in the chain, which applies to the chains target component.
         *
         * @return leaf link
         */
        public Link getLeafLink()
        {
            return chainLinks.get(chainLinks.size() - 1);
        }

        /**
         * Return the {@link OpenPGPComponentKey} to which the leaf link applies to.
         * For subkey binding signatures, this is the subkey.
         * For user-id certification signatures, it is the primary key.
         *
         * @return target key component of the leaf link
         */
        public OpenPGPComponentKey getLeafLinkTargetKey()
        {
            return getSignature().getTargetKeyComponent();
        }

        /**
         * Return true, if the chain only consists of non-revocation signatures and is therefore a certification chain.
         *
         * @return true if the chain is a certification, false if it contains a revocation link.
         */
        public boolean isCertification()
        {
            for (Iterator<Link> it = chainLinks.iterator(); it.hasNext(); )
            {
                if (it.next() instanceof Revocation)
                {
                    return false;
                }
            }
            return true;
        }

        /**
         * Return true, if the chain contains at least one revocation signature.
         *
         * @return true if the chain is a revocation.
         */
        public boolean isRevocation()
        {
            for (Iterator<Link> it = chainLinks.iterator(); it.hasNext(); )
            {
                if (it.next() instanceof Revocation)
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * Return true, if the chain contains at least one link that represents a hard revocation.
         *
         * @return true if chain is hard revocation, false if it is a certification or soft revocation
         */
        public boolean isHardRevocation()
        {
            for (Iterator<Link> it = chainLinks.iterator(); it.hasNext(); )
            {
                if (it.next().signature.signature.isHardRevocation())
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * Return the date since which this signature chain is valid.
         * This is the creation time of the most recent link in the chain.
         *
         * @return most recent signature creation time
         */
        public Date getSince()
        {
            Date latestDate = null;
            for (Iterator it = chainLinks.iterator(); it.hasNext(); )
            {
                Link link = (Link)it.next();
                OpenPGPComponentSignature signature = link.getSignature();
                Date currentDate = signature.getCreationTime();
                if (latestDate == null || currentDate.after(latestDate))
                {
                    latestDate = currentDate;
                }
            }
            return latestDate;
        }
//        public Date getSince()
//        {
//            // Find most recent chain link
////            return chainLinks.stream()
////                .map(it -> it.signature)
////                .max(Comparator.comparing(OpenPGPComponentSignature::getCreationTime))
////                .map(OpenPGPComponentSignature::getCreationTime)
////                .orElse(null);
//            return chainLinks.stream()
//                .map(new Function<Link, Object>()
//                {
//                    @Override
//                    public OpenPGPComponentSignature apply(Link it)
//                    {
//                        return it.signature; // Replace lambda: `it -> it.signature`
//                    }
//
//                })
//                .max(new Comparator<Object>()
//                {
//                    @Override
//                    public int compare(Object o1, Object o2)
//                    {
//                        // Replace method reference: `Comparator.comparing(OpenPGPComponentSignature::getCreationTime)`
//                        return ((OpenPGPComponentSignature)o1).getCreationTime().compareTo(((OpenPGPComponentSignature)o2).getCreationTime());
//                    }
//                })
//                .map(new Function<Object, Date>()
//                {
//                    @Override
//                    public Date apply(Object sig)
//                    {
//                        return ((OpenPGPComponentSignature)sig).getCreationTime(); // Replace method reference: `OpenPGPComponentSignature::getCreationTime`
//                    }
//                })
//                .orElse(null);
//        }

        /**
         * Return the date until which the chain link is valid.
         * This is the earliest expiration time of any signature in the chain.
         *
         * @return earliest expiration time
         */
        public Date getUntil()
        {
            Date soonestExpiration = null;
            for (Iterator<Link> it = chainLinks.iterator(); it.hasNext(); )
            {
                Link link = it.next();
                Date until = link.until();
                if (until != null)
                {
                    soonestExpiration = (soonestExpiration == null) ? until :
                        (until.before(soonestExpiration) ? until : soonestExpiration);
                }
            }
            return soonestExpiration;
        }

        /**
         * Return true if the chain is effective at the given evaluation date, meaning all link signatures have
         * been created before the evaluation time, and none signature expires before the evaluation time.
         *
         * @param evaluationDate reference time
         * @return true if chain is effective at evaluation date
         */
        public boolean isEffectiveAt(Date evaluationDate)
        {
            if (isHardRevocation())
            {
                return true;
            }
            Date since = getSince();
            Date until = getUntil();
            // since <= eval <= until
            return !evaluationDate.before(since) && (until == null || !evaluationDate.after(until));
        }

        /**
         * Return true if the signature chain is valid, meaning all its chain links are valid.
         *
         * @return true if chain is valid
         * @throws PGPSignatureException if an exception occurs during signature verification
         */
        public boolean isValid()
            throws PGPSignatureException
        {
            OpenPGPComponentKey rootKey = getRootLinkIssuer();
            if (rootKey == null)
            {
                throw new MissingIssuerCertException(getRootLink().signature, "Missing issuer certificate.");
            }
            OpenPGPCertificate cert = rootKey.getCertificate();
            return isValid(cert.implementation.pgpContentVerifierBuilderProvider(), cert.policy);
        }

        /**
         * Return true if the signature chain is valid, meaning all its chain links are valid.
         *
         * @param contentVerifierBuilderProvider provider for content verifier builders
         * @param policy                         algorithm policy
         * @return true if chain is valid
         * @throws PGPSignatureException if an exception occurs during signature verification
         */
        public boolean isValid(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider, OpenPGPPolicy policy)
            throws PGPSignatureException
        {
            boolean correct = true;
            for (Iterator<Link> it = chainLinks.iterator(); it.hasNext(); )
            {
                Link link = it.next();
                if (!link.signature.isTested)
                {
                    link.verify(contentVerifierBuilderProvider, policy);
                }

                if (!link.signature.isCorrect)
                {
                    correct = false;
                }
            }
            return correct;
        }

        @Override
        public String toString()
        {
            StringBuilder b = new StringBuilder();
            String until = getUntil() == null ? "EndOfTime" : UTCUtil.format(getUntil());
            b.append("From ").append(UTCUtil.format(getSince())).append(" until ").append(until).append("\n");
            for (Iterator<Link> it = chainLinks.iterator(); it.hasNext(); )
            {
                Link link = it.next();
                b.append("  ").append(link.toString()).append("\n");
            }
            return b.toString();
        }

        @Override
        public int compareTo(OpenPGPSignatureChain other)
        {
            if (this == other)
            {
                return 0;
            }

            if (isHardRevocation())
            {
                return -1;
            }

            if (other.isHardRevocation())
            {
                return 1;
            }

            int compare = -getRootLink().since().compareTo(other.getRootLink().since());
            if (compare != 0)
            {
                return compare;
            }

            compare = -getLeafLink().since().compareTo(other.getLeafLink().since());
            if (compare != 0)
            {
                return compare;
            }

            if (isRevocation())
            {
                return 1;
            }
            return -1;
        }

        @Override
        public Iterator<Link> iterator()
        {
            return chainLinks.iterator();
        }

        /**
         * Link in a {@link OpenPGPSignatureChain}.
         */
        public static abstract class Link
        {
            protected final OpenPGPComponentSignature signature;

            public Link(OpenPGPComponentSignature signature)
            {
                this.signature = signature;
            }

            /**
             * Return the {@link Date} since when the link is effective.
             * This is the creation time of the signature.
             *
             * @return signature creation time
             */
            public Date since()
            {
                return signature.getCreationTime();
            }

            /**
             * Return the {@link Date} until the signature is effective.
             * This is, depending on which event is earlier in time, either the signature expiration time,
             * or the key expiration time.
             *
             * @return time until the link is valid
             */
            public Date until()
            {
                Date backSigExpiration = getBackSigExpirationTime();
                Date expirationTime = signature.getExpirationTime();

                if (expirationTime == null)
                {
                    return backSigExpiration;
                }

                if (backSigExpiration == null || expirationTime.before(backSigExpiration))
                {
                    return expirationTime;
                }
                return backSigExpiration;
            }

            /**
             * Return the expiration time of the primary key binding signature.
             *
             * @return primary key binding signature expiration time
             */
            private Date getBackSigExpirationTime()
            {
                if (signature.getSignature().getSignatureType() != PGPSignature.SUBKEY_BINDING)
                {
                    return null;
                }

                PGPSignatureSubpacketVector hashedSubpackets = signature.getSignature().getHashedSubPackets();
                if (hashedSubpackets == null)
                {
                    return null;
                }

                int keyFlags = signature.getSignature().getHashedSubPackets().getKeyFlags();
                if ((keyFlags & KeyFlags.SIGN_DATA) != KeyFlags.SIGN_DATA)
                {
                    return null;
                }

                try
                {
                    PGPSignatureList embeddedSigs = hashedSubpackets.getEmbeddedSignatures();
                    if (!embeddedSigs.isEmpty())
                    {
                        OpenPGPComponentSignature backSig = new OpenPGPComponentSignature(
                            embeddedSigs.get(0),
                            // Primary Key Binding Signature has issuer and target swapped
                            /* issuer= */getSignature().getTargetKeyComponent(),
                            /* target= */getSignature().getIssuer());
                        return backSig.getExpirationTime();
                    }
                    return null;
                }
                catch (PGPException e)
                {
                    return null;
                }
            }

            /**
             * Verify the link signature.
             *
             * @param contentVerifierBuilderProvider provider for content verifier builders
             * @param policy                         algorithm policy
             * @return true if the signature is valid, false otherwise
             * @throws PGPSignatureException if an exception occurs during signature verification
             */
            public boolean verify(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider,
                                  OpenPGPPolicy policy)
                throws PGPSignatureException
            {
                signature.verify(contentVerifierBuilderProvider, policy); // throws if invalid
                return true;
            }

            @Override
            public String toString()
            {
                return signature.toString();
            }

            /**
             * Factory method for creating Links from component signatures.
             * Returns either a {@link Certification} in case the signature is a binding,
             * or a {@link Revocation} in case the signature is a revocation signature.
             *
             * @param signature component signature
             * @return link
             */
            public static Link create(OpenPGPComponentSignature signature)
            {
                if (signature.isRevocation())
                {
                    return new Revocation(signature);
                }
                else
                {
                    return new Certification(signature);
                }
            }

            /**
             * Return the signature of the link.
             *
             * @return signature
             */
            public OpenPGPComponentSignature getSignature()
            {
                return signature;
            }
        }

        /**
         * "Positive" signature chain link.
         */
        public static class Certification
            extends Link
        {
            /**
             * Positive certification.
             *
             * @param signature signature
             */
            public Certification(OpenPGPComponentSignature signature)
            {
                super(signature);
            }
        }

        /**
         * "Negative" signature chain link.
         */
        public static class Revocation
            extends Link
        {
            /**
             * Revocation.
             *
             * @param signature signature
             */
            public Revocation(OpenPGPComponentSignature signature)
            {
                super(signature);
            }

            @Override
            public Date since()
            {
                if (signature.signature.isHardRevocation())
                {
                    // hard revocations are valid retroactively, so we return the beginning of time here
                    return new Date(0L);
                }
                return super.since();
            }

            @Override
            public Date until()
            {
                if (signature.signature.isHardRevocation())
                {
                    // hard revocations do not expire, so they are effective indefinitely
                    return new Date(Long.MAX_VALUE);
                }
                return super.until();
            }
        }
    }

    /**
     * Collection of multiple {@link OpenPGPSignatureChain} objects.
     */
    public static class OpenPGPSignatureChains
        implements Iterable<OpenPGPSignatureChain>
    {
        private final OpenPGPCertificateComponent targetComponent;
        private final Set<OpenPGPSignatureChain> chains = new TreeSet<OpenPGPSignatureChain>();

        public OpenPGPSignatureChains(OpenPGPCertificateComponent component)
        {
            this.targetComponent = component;
        }

        /**
         * Add a single chain to the collection.
         *
         * @param chain chain
         */
        public void add(OpenPGPSignatureChain chain)
        {
            this.chains.add(chain);
        }

        /**
         * Add all chains to the collection.
         *
         * @param otherChains other chains
         */
        public void addAll(OpenPGPSignatureChains otherChains)
        {
            this.chains.addAll(otherChains.chains);
        }

        /**
         * Return true if the collection is empty.
         *
         * @return true if empty
         */
        public boolean isEmpty()
        {
            return chains.isEmpty();
        }

        /**
         * Return a positive certification chain for the component for the given evaluationTime.
         *
         * @param evaluationTime time for which validity of the {@link OpenPGPCertificateComponent} is checked.
         * @return positive certification chain or null
         */
        public OpenPGPSignatureChain getCertificationAt(Date evaluationTime)
        {
            for (Iterator<OpenPGPSignatureChain> it = chains.iterator(); it.hasNext(); )
            {
                OpenPGPSignatureChain chain = it.next();
                boolean isEffective = chain.isEffectiveAt(evaluationTime);
                boolean isCertification = chain.isCertification();
                if (isEffective && isCertification)
                {
                    return chain;
                }
            }
            return null;
        }

        /**
         * Return all {@link OpenPGPSignatureChain} objects, which are valid at the given evaluation time.
         *
         * @param evaluationTime reference time
         * @return valid chains at reference time
         */
        public OpenPGPSignatureChains getChainsAt(Date evaluationTime)
        {
            OpenPGPSignatureChains effectiveChains = new OpenPGPSignatureChains(targetComponent);
            for (Iterator<OpenPGPSignatureChain> it = chains.iterator(); it.hasNext(); )
            {
                OpenPGPSignatureChain chain = it.next();
                if (chain.isEffectiveAt(evaluationTime))
                {
                    effectiveChains.add(chain);
                }
            }
            return effectiveChains;
        }

        /**
         * Return a negative certification chain for the component for the given evaluationTime.
         *
         * @param evaluationTime time for which revocation-ness of the {@link OpenPGPCertificateComponent} is checked.
         * @return negative certification chain or null
         */
        public OpenPGPSignatureChain getRevocationAt(Date evaluationTime)
        {
            for (Iterator<OpenPGPSignatureChain> it = chains.iterator(); it.hasNext(); )
            {
                OpenPGPSignatureChain chain = it.next();
                if (chain.isRevocation() && chain.isEffectiveAt(evaluationTime))
                {
                    return chain;
                }
            }
            return null;
        }

        @Override
        public String toString()
        {
            StringBuilder b = new StringBuilder(targetComponent.toDetailString())
                .append(" is bound with ").append(chains.size()).append(" chains:").append("\n");
            for (Iterator<OpenPGPSignatureChain> it = chains.iterator(); it.hasNext(); )
            {
                OpenPGPSignatureChain chain = it.next();
                b.append(chain.toString());
            }
            return b.toString();
        }

        /**
         * Return all {@link OpenPGPSignatureChain} items which originate from the root {@link OpenPGPComponentKey}.
         *
         * @param root root key
         * @return all chains with root key as origin
         */
        public OpenPGPSignatureChains fromOrigin(OpenPGPComponentKey root)
        {
            OpenPGPSignatureChains chainsFromRoot = new OpenPGPSignatureChains(root);
            for (Iterator<OpenPGPSignatureChain> it = chains.iterator(); it.hasNext(); )
            {
                OpenPGPSignatureChain chain = it.next();
                if (chain.getRootLinkIssuer() == root)
                {
                    chainsFromRoot.add(chain);
                }
            }
            return chainsFromRoot;
        }

        /**
         * Return the latest chain, which is valid at the given evaluation time.
         *
         * @param evaluationDate reference time
         * @return latest valid chain
         */
        public OpenPGPSignatureChain getChainAt(Date evaluationDate)
        {
            OpenPGPSignatureChains atDate = getChainsAt(evaluationDate);
            Iterator<OpenPGPSignatureChain> it = atDate.chains.iterator();
            if (it.hasNext())
            {
                return it.next();
            }
            return null;
        }

        @Override
        public Iterator<OpenPGPSignatureChain> iterator()
        {
            return chains.iterator();
        }
    }

    private interface KeyFilter
    {
        boolean test(OpenPGPComponentKey key, Date evaluationTime);
    }

    private List<OpenPGPComponentKey> filterKeys(Date evaluationTime, KeyFilter filter)
    {
        List<OpenPGPComponentKey> result = new ArrayList<OpenPGPComponentKey>();
        for (Iterator<OpenPGPComponentKey> it = getKeys().iterator(); it.hasNext(); )
        {
            OpenPGPComponentKey key = it.next();
            if (isBound(key, evaluationTime) && filter.test(key, evaluationTime))
            {
                result.add(key);
            }
        }
        return result;
    }

    private void addSignaturesToChains(List<OpenPGPComponentSignature> signatures, OpenPGPSignatureChains chains)
    {
        for (Iterator<OpenPGPComponentSignature> it = signatures.iterator(); it.hasNext(); )
        {
            chains.add(OpenPGPSignatureChain.direct(it.next()));
        }
    }
}
