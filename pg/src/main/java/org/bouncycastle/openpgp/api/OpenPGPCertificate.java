package org.bouncycastle.openpgp.api;

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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

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

    private final PGPKeyRing keyRing;

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
     * @param keyRing public key ring
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
     * @param keyRing public key ring
     * @param implementation OpenPGP implementation
     * @param policy OpenPGP policy
     */
    public OpenPGPCertificate(PGPKeyRing keyRing, OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        this.implementation = implementation;
        this.policy = policy;

        this.keyRing = keyRing;
        this.subkeys = new HashMap<>();
        this.componentSignatureChains = new LinkedHashMap<>();

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

    public boolean isSecretKey()
    {
        return false;
    }

    public List<OpenPGPUserId> getAllUserIds()
    {
        return getPrimaryKey().getUserIDs();
    }

    public List<OpenPGPUserId> getValidUserIds()
    {
        return getValidUserIds(new Date());
    }

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
        Map<KeyIdentifier, OpenPGPComponentKey> keys = new HashMap<>();
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
        return new HashMap<>(subkeys);
    }

    public List<OpenPGPComponentKey> getComponentKeysWithFlag(Date evaluationTime, int... keyFlags)
    {
        List<OpenPGPComponentKey> componentKeys = new ArrayList<>();
        for (OpenPGPComponentKey k : getKeys())
        {
            if (k.isBoundAt(evaluationTime) && k.hasKeyFlags(evaluationTime, keyFlags))
            {
                componentKeys.add(k);
            }
        }
        return componentKeys;
    }

    /**
     * Return a {@link List} containing all {@link OpenPGPCertificateComponent components} of the certificate.
     * Components are primary key, subkeys and identities (user-ids, user attributes).
     *
     * @return list of components
     */
    public List<OpenPGPCertificateComponent> getComponents()
    {
        return new ArrayList<>(componentSignatureChains.keySet());
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
        List<OpenPGPComponentKey> keys = new ArrayList<>();
        keys.add(primaryKey);
        keys.addAll(subkeys.values());
        return keys;
    }

    public List<OpenPGPComponentKey> getValidKeys()
    {
        return getValidKeys(new Date());
    }

    public List<OpenPGPComponentKey> getValidKeys(Date evaluationTime)
    {
        List<OpenPGPComponentKey> validKeys = new ArrayList<>();
        for (OpenPGPComponentKey k : getKeys())
        {
            if (k.isBoundAt(evaluationTime))
            {
                validKeys.add(k);
            }
        }
        return validKeys;
    }

    /**
     * Return the {@link OpenPGPComponentKey} identified by the passed in {@link KeyIdentifier}.
     *
     * @param identifier key identifier
     * @return component key
     */
    public OpenPGPComponentKey getKey(KeyIdentifier identifier)
    {
        if (identifier.matches(getPrimaryKey().getPGPPublicKey().getKeyIdentifier()))
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
        // issuer is primary key
        if (KeyIdentifier.matches(keyIdentifiers, getPrimaryKey().getKeyIdentifier(), true))
        {
            return primaryKey;
        }

        for (KeyIdentifier subkeyIdentifier : subkeys.keySet())
        {
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
            return (PGPPublicKeyRing) keyRing;
        }

        List<PGPPublicKey> list = new ArrayList<>();
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
     * @return all keys identifiers
     */
    public List<KeyIdentifier> getAllKeyIdentifiers()
    {
        List<KeyIdentifier> identifiers = new ArrayList<>();
        for (Iterator<PGPPublicKey> it = keyRing.getPublicKeys(); it.hasNext(); )
        {
            PGPPublicKey key = it.next();
            identifiers.add(key.getKeyIdentifier());
        }
        return identifiers;
    }

    public OpenPGPComponentSignature getCertification()
    {
        return getCertification(new Date());
    }

    public OpenPGPComponentSignature getCertification(Date evaluationTime)
    {
        return primaryKey.getCertification(evaluationTime);
    }

    public OpenPGPComponentSignature getRevocation()
    {
        return getRevocation(new Date());
    }

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
        for (OpenPGPCertificateComponent component : getComponents())
        {
            OpenPGPSignatureChains componentChains = getAllSignatureChainsFor(component);
            if (componentChains == null)
            {
                continue;
            }
            componentChains = componentChains.getChainsAt(evaluationTime);
            for (OpenPGPSignatureChain chain : componentChains)
            {
                for (OpenPGPSignatureChain.Link link : chain)
                {
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
        for (OpenPGPComponentKey key : getKeys())
        {
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
                PGPPublicKeyRing publicKeys = (PGPPublicKeyRing) next;
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
                PGPSignatureList signatures = (PGPSignatureList) next;

                PGPPublicKeyRing publicKeys = certificate.getPGPPublicKeyRing();
                PGPPublicKey primaryKey = publicKeys.getPublicKey();
                for (PGPSignature signature : signatures)
                {
                    primaryKey = PGPPublicKey.addCertification(primaryKey, signature);
                }
                publicKeys = PGPPublicKeyRing.insertPublicKey(publicKeys, primaryKey);
                return new OpenPGPCertificate(publicKeys, certificate.implementation);
            }
        }
        return null;
    }

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
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream.Builder armorBuilder = ArmoredOutputStream.builder()
                .clearHeaders();
        // Add fingerprint comment
        armorBuilder.addSplitMultilineComment(getPrettyFingerprint());

        // Add user-id comments
        for (OpenPGPUserId userId : getPrimaryKey().getUserIDs())
        {
            armorBuilder.addEllipsizedComment(userId.getUserId());
        }

        ArmoredOutputStream aOut = armorBuilder.build(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);

        // Make sure we export a TPK
        List<PGPPublicKey> list = new ArrayList<>();
        for (Iterator<PGPPublicKey> it = getPGPKeyRing().getPublicKeys(); it.hasNext(); )
        {
            list.add(it.next());
        }
        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(list);

        publicKeys.encode(pOut, true);
        pOut.close();
        aOut.close();
        return bOut.toString();
    }

    private OpenPGPSignatureChain getSignatureChainFor(OpenPGPCertificateComponent component,
                                                       OpenPGPComponentKey origin,
                                                       Date evaluationDate)
    {
        // Check if there are signatures at all for the component
        OpenPGPSignatureChains chainsForComponent = getAllSignatureChainsFor(component);
        if (component == getPrimaryKey() && chainsForComponent.isEmpty())
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

    private OpenPGPSignatureChains getAllSignatureChainsFor(OpenPGPCertificateComponent component)
    {
        OpenPGPSignatureChains chains = new OpenPGPSignatureChains(component.getPublicComponent());
        chains.addAll(componentSignatureChains.get(component.getPublicComponent()));
        return chains;
    }

    private void processPrimaryKey(OpenPGPPrimaryKey primaryKey)
    {
        OpenPGPSignatureChains keySignatureChains = new OpenPGPSignatureChains(primaryKey);
        List<OpenPGPComponentSignature> keySignatures = primaryKey.getKeySignatures();

        // Key Signatures
        for (OpenPGPComponentSignature sig : keySignatures)
        {
            OpenPGPSignatureChain chain = OpenPGPSignatureChain.direct(sig, sig.issuer, primaryKey);
            keySignatureChains.add(chain);
        }
        componentSignatureChains.put(primaryKey, keySignatureChains);

        // Identities
        for (OpenPGPIdentityComponent identity : primaryKey.identityComponents)
        {
            OpenPGPSignatureChains identityChains = new OpenPGPSignatureChains(identity);
            List<OpenPGPComponentSignature> bindings;

            if (identity instanceof OpenPGPUserId)
            {
                bindings = primaryKey.getUserIdSignatures((OpenPGPUserId) identity);
            }
            else
            {
                bindings = primaryKey.getUserAttributeSignatures((OpenPGPUserAttribute) identity);
            }

            for (OpenPGPComponentSignature sig : bindings)
            {
                OpenPGPSignatureChain chain = OpenPGPSignatureChain.direct(sig, sig.getIssuerComponent(), identity);
                identityChains.add(chain);
            }
            componentSignatureChains.put(identity, identityChains);
        }
    }

    private void processSubkey(OpenPGPSubkey subkey)
    {
        List<OpenPGPComponentSignature> bindingSignatures = subkey.getKeySignatures();
        OpenPGPSignatureChains subkeyChains = new OpenPGPSignatureChains(subkey);

        for (OpenPGPComponentSignature sig : bindingSignatures)
        {
            OpenPGPComponentKey issuer = subkey.getCertificate().getSigningKeyFor(sig.getSignature());
            if (issuer == null)
            {
                continue; // external key
            }

            OpenPGPSignatureChains issuerChains = getAllSignatureChainsFor(issuer);
            if (!issuerChains.chains.isEmpty())
            {
                for (OpenPGPSignatureChain issuerChain : issuerChains.chains)
                {
                    subkeyChains.add(issuerChain.plus(sig, subkey));
                }
            }
            else
            {
                subkeyChains.add(new OpenPGPSignatureChain(
                        new OpenPGPSignatureChain.Certification(sig, issuer, subkey)));
            }
        }
        this.componentSignatureChains.put(subkey, subkeyChains);
    }

    /**
     * Return true, if the passed in component is - at evaluation time - properly bound to the certificate.
     *
     * @param component OpenPGP certificate component
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
     * @param component OpenPGP certificate component
     * @param root root certificate component
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
            KeyExpirationTime kexp = (KeyExpirationTime) keyExpiration.getSubpacket();
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
        List<OpenPGPComponentKey> encryptionKeys = new ArrayList<>();

        for (OpenPGPComponentKey key : getKeys())
        {
            if (!isBound(key, evaluationTime))
            {
                // Key is not bound
                continue;
            }

            if (!key.isEncryptionKey(evaluationTime))
            {
                continue;
            }

            encryptionKeys.add(key);
        }

        return encryptionKeys;
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
        List<OpenPGPComponentKey> signingKeys = new ArrayList<>();

        for (OpenPGPComponentKey key : getKeys())
        {
            if (!isBound(key, evaluationTime))
            {
                // Key is not bound
                continue;
            }

            if (!key.isSigningKey(evaluationTime))
            {
                continue;
            }

            signingKeys.add(key);
        }

        return signingKeys;
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

        List<OpenPGPSignatureChain> uidBindings = new ArrayList<>();
        for (OpenPGPUserId userId : getPrimaryKey().getUserIDs())
        {
            OpenPGPSignatureChain uidBinding = getAllSignatureChainsFor(userId)
                    .fromOrigin(getPrimaryKey())
                    .getCertificationAt(evaluationTime);

            if (uidBinding != null)
            {
                uidBindings.add(uidBinding);
            }
        }

        uidBindings.sort(Comparator.comparing(OpenPGPSignatureChain::getSince).reversed());
        for (OpenPGPSignatureChain binding : uidBindings)
        {
            PGPSignature sig = binding.getHeadLink().getSignature().getSignature();
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
        return new ArrayList<>(primaryKey.identityComponents);
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
     * @param userId user-id
     * @return user-id
     */
    public OpenPGPUserId getUserId(String userId)
    {
        for (OpenPGPUserId uid : primaryKey.getUserIDs())
        {
            if (uid.getUserId().equals(userId))
            {
                return uid;
            }
        }
        return null;
    }

    public Date getExpirationTime()
    {
        return getExpirationTime(new Date());
    }

    public Date getExpirationTime(Date evaluationTime)
    {
        return getPrimaryKey().getKeyExpirationDateAt(evaluationTime);
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
                OpenPGPPrimaryKey pk = (OpenPGPPrimaryKey) getPublicComponent();
                if (!pk.getUserIDs().isEmpty())
                {
                    chains.addAll(getCertificate().getAllSignatureChainsFor(pk.getUserIDs().get(0)));
                }
            }
            return chains;
        }

        public OpenPGPComponentSignature getCertification(Date evaluationTime)
        {
            OpenPGPSignatureChain certification = getSignatureChains().getCertificationAt(evaluationTime);
            if (certification != null)
            {
                return certification.getSignature();
            }
            return null;
        }

        public OpenPGPComponentSignature getRevocation(Date evaluationTime)
        {
            OpenPGPSignatureChain revocation = getSignatureChains().getRevocationAt(evaluationTime);
            if (revocation != null)
            {
                return revocation.getSignature();
            }
            return null;
        }

        public OpenPGPComponentSignature getLatestSelfSignature()
        {
            return getLatestSelfSignature(new Date());
        }

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

        protected abstract OpenPGPComponentKey getKeyComponent();

        /**
         * Return the {@link SignatureSubpacket} instance of the given subpacketType, which currently applies to
         * the key. Since subpackets from the Direct-Key signature apply to all subkeys of a certificate,
         * this method first inspects the signature that immediately applies to this key (e.g. a subkey-binding
         * signature), and - if the queried subpacket is found in there, returns that instance.
         * Otherwise, indirectly applying signatures (e.g. Direct-Key signatures) are queried.
         * That way, preferences from the direct-key signature are considered, but per-key overwrites take precedence.
         *
         * @see <a href="https://openpgp.dev/book/adv/verification.html#attribute-shadowing">
         *     OpenPGP for application developers - Attribute Shadowing</a>
         *
         * @param evaluationTime evaluation time
         * @param subpacketType subpacket type that is being searched for
         * @return subpacket from directly or indirectly applying signature
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
            OpenPGPComponentSignature keySignature = binding.getHeadLink().getSignature();

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
                keySignature = preferenceBinding.getHeadLink().signature;
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
         * @param signature signature
         * @param issuer key that issued the signature.
         *              Is nullable (e.g. for 3rd party sigs where the certificate is not available).
         * @param target signed certificate component
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
                return ((OpenPGPIdentityComponent) getTargetComponent()).getPrimaryKey();
            }
            if (getTargetComponent() instanceof OpenPGPComponentKey)
            {
                // Key signatures authenticate the target key
                return (OpenPGPComponentKey) getTargetComponent();
            }
            throw new IllegalArgumentException("Unknown target type.");
        }

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
         * @param contentVerifierBuilderProvider provider for verifiers
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
            if (signature.getSignatureType() == PGPSignature.DIRECT_KEY)
            {
                verifyKeySignature(
                        issuer,
                        issuer,
                        contentVerifierBuilderProvider);
            }

            // Subkey binding signature
            else if (signature.getSignatureType() == PGPSignature.SUBKEY_BINDING)
            {
                // For signing-capable subkeys, check the embedded primary key binding signature
                verifyEmbeddedPrimaryKeyBinding(contentVerifierBuilderProvider, policy, getCreationTime());

                // Binding signature MUST NOT predate the subkey itself
                if (((OpenPGPSubkey) target).getCreationTime().after(signature.getCreationTime()))
                {
                    isCorrect = false;
                    throw new MalformedOpenPGPSignatureException(this, "Subkey binding signature predates subkey creation time.");
                }

                verifyKeySignature(
                        issuer,
                        (OpenPGPSubkey) target,
                        contentVerifierBuilderProvider);
            }

            // User-ID binding
            else if (target instanceof OpenPGPUserId)
            {
                verifyUserIdSignature(
                        issuer,
                        (OpenPGPUserId) target,
                        contentVerifierBuilderProvider);
            }

            // User-Attribute binding
            else if (target instanceof OpenPGPUserAttribute)
            {
                verifyUserAttributeSignature(
                        issuer,
                        (OpenPGPUserAttribute) target,
                        contentVerifierBuilderProvider);
            }

            else
            {
                throw new PGPSignatureException("Unexpected signature type: " + getType());
            }
        }

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
            List<PGPSignature> embeddedSignatures = new ArrayList<>();
            try
            {
                PGPSignatureList sigList = signature.getHashedSubPackets().getEmbeddedSignatures();
                for (PGPSignature pgpSignature : sigList)
                {
                    embeddedSignatures.add(pgpSignature);
                }
                sigList = signature.getUnhashedSubPackets().getEmbeddedSignatures();
                for (PGPSignature pgpSignature : sigList)
                {
                    embeddedSignatures.add(pgpSignature);
                }
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
            for (PGPSignature primaryKeyBinding : embeddedSignatures)
            {
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
                    continue;
                }
            }

            // if we end up here, it means we have only found invalid sigs
            throw exception;
        }

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
                if (issuer == target)
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
        }

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
        }

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
     *     OpenPGP for Application Developers - Layers of keys in OpenPGP</a>
     */
    public static abstract class OpenPGPComponentKey
            extends OpenPGPCertificateComponent
    {
        protected final PGPPublicKey rawPubkey;

        /**
         * Constructor.
         * @param rawPubkey public key
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
                return currentDKChain.getHeadLink().getSignature();
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

        /**
         * Return the {@link KeyFlags} signature subpacket that currently applies to the key.
         * @return key flags subpacket
         */
        public KeyFlags getKeyFlags()
        {
            return getKeyFlags(new Date());
        }

        /**
         * Return the {@link KeyFlags} signature subpacket that - at evaluation time - applies to the key.
         * @param evaluationTime evaluation time
         * @return key flags subpacket
         */
        public KeyFlags getKeyFlags(Date evaluationTime)
        {
            OpenPGPSignature.OpenPGPSignatureSubpacket subpacket = getApplyingSubpacket(
                    evaluationTime, SignatureSubpacketTags.KEY_FLAGS);
            if (subpacket != null)
            {
                return (KeyFlags) subpacket.getSubpacket();
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
         * @param flags key flags (see {@link KeyFlags} for possible values)
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
            for (int f : flags)
            {
                if (((keyFlags.getFlags() & f) == f))
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * Return the {@link Features} signature subpacket that currently applies to the key.
         * @return feature signature subpacket
         */
        public Features getFeatures()
        {
            return getFeatures(new Date());
        }

        /**
         * Return the {@link Features} signature subpacket that - at evaluation time - applies to the key.
         * @param evaluationTime evaluation time
         * @return features subpacket
         */
        public Features getFeatures(Date evaluationTime)
        {
            OpenPGPSignature.OpenPGPSignatureSubpacket subpacket = getApplyingSubpacket(evaluationTime, SignatureSubpacketTags.FEATURES);
            if (subpacket != null)
            {
                return (Features) subpacket.getSubpacket();
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
                return (PreferredAEADCiphersuites) subpacket.getSubpacket();
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
                return (PreferredAlgorithms) subpacket.getSubpacket();
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
                return (PreferredAlgorithms) subpacket.getSubpacket();
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
            OpenPGPComponentKey other = (OpenPGPComponentKey) obj;
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
            this.identityComponents = new ArrayList<>();

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

        public OpenPGPComponentSignature getLatestDirectKeySelfSignature()
        {
            return getLatestDirectKeySelfSignature(new Date());
        }

        public OpenPGPComponentSignature getLatestDirectKeySelfSignature(Date evaluationTime)
        {
            OpenPGPSignatureChain currentDKChain = getCertificate().getAllSignatureChainsFor(this)
                    .getCertificationAt(evaluationTime);
            if (currentDKChain != null && !currentDKChain.chainLinks.isEmpty())
            {
                return currentDKChain.getHeadLink().getSignature();
            }

            return null;
        }

        public OpenPGPComponentSignature getLatestKeyRevocationSignature()
        {
            return getLatestKeyRevocationSignature(new Date());
        }

        public OpenPGPComponentSignature getLatestKeyRevocationSignature(Date evaluationTime)
        {
            OpenPGPSignatureChain currentRevocationChain = getCertificate().getAllSignatureChainsFor(this)
                    .getRevocationAt(evaluationTime);
            if (currentRevocationChain != null && !currentRevocationChain.chainLinks.isEmpty())
            {
                return currentRevocationChain.getHeadLink().getSignature();
            }
            return null;
        }

        @Override
        public OpenPGPComponentSignature getLatestSelfSignature(Date evaluationTime)
        {
            List<OpenPGPComponentSignature> signatures = new ArrayList<>();

            OpenPGPComponentSignature directKeySig = getLatestDirectKeySelfSignature(evaluationTime);
            if (directKeySig != null)
            {
                signatures.add(directKeySig);
            }

            OpenPGPComponentSignature keyRevocation = getLatestKeyRevocationSignature(evaluationTime);
            if (keyRevocation != null)
            {
                signatures.add(keyRevocation);
            }

            for (OpenPGPIdentityComponent identity : getCertificate().getIdentities())
            {
                OpenPGPComponentSignature identitySig = identity.getLatestSelfSignature(evaluationTime);
                if (identitySig != null)
                {
                    signatures.add(identitySig);
                }
            }

            OpenPGPComponentSignature latest = null;
            for (OpenPGPComponentSignature signature : signatures)
            {
                if (latest == null || signature.getCreationTime().after(latest.getCreationTime()))
                {
                    latest = signature;
                }
            }
            return latest;
        }

        @Override
        protected OpenPGPComponentKey getKeyComponent()
        {
            return this;
        }

        /**
         * Return all {@link OpenPGPUserId OpenPGPUserIds} on this key.
         *
         * @return user ids
         */
        public List<OpenPGPUserId> getUserIDs()
        {
            List<OpenPGPUserId> userIds = new ArrayList<>();
            for (OpenPGPIdentityComponent identity : identityComponents)
            {
                if (identity instanceof OpenPGPUserId)
                {
                    userIds.add((OpenPGPUserId) identity);
                }
            }
            return userIds;
        }

        public List<OpenPGPUserId> getValidUserIds()
        {
            return getValidUserIDs(new Date());
        }

        public List<OpenPGPUserId> getValidUserIDs(Date evaluationTime)
        {
            List<OpenPGPUserId> userIds = new ArrayList<>();
            for (OpenPGPIdentityComponent identity : identityComponents)
            {
                if (identity instanceof OpenPGPUserId && identity.isBoundAt(evaluationTime))
                {
                    userIds.add((OpenPGPUserId) identity);
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

            for (OpenPGPUserId userId : getUserIDs())
            {
                OpenPGPSignature.OpenPGPSignatureSubpacket subpacket =
                        userId.getApplyingSubpacket(evaluationTime, SignatureSubpacketTags.PRIMARY_USER_ID);
                if (subpacket == null)
                {
                    // Not bound at this time, or not explicit
                    continue;
                }

                PrimaryUserID primaryUserId = (PrimaryUserID) subpacket.getSubpacket();
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

            for (OpenPGPUserId userId : getUserIDs())
            {
                OpenPGPSignatureChain chain = userId.getSignatureChains()
                        .getCertificationAt(evaluationTime);
                if (chain == null)
                {
                    // Not valid at this time
                    continue;
                }

                OpenPGPSignature binding = chain.getHeadLink().getSignature();
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
            List<OpenPGPUserAttribute> userAttributes = new ArrayList<>();
            for (OpenPGPIdentityComponent identity : identityComponents)
            {
                if (identity instanceof OpenPGPUserAttribute)
                {
                    userAttributes.add((OpenPGPUserAttribute) identity);
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
            List<OpenPGPCertificate.OpenPGPComponentSignature> list = new ArrayList<>();
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
            List<OpenPGPCertificate.OpenPGPComponentSignature> list = new ArrayList<>();
            while (iterator.hasNext())
            {
                PGPSignature sig = iterator.next();
                // try to find issuer for self-signature
                OpenPGPCertificate.OpenPGPComponentKey issuer = getCertificate()
                        .getSigningKeyFor(sig);

                list.add(new OpenPGPCertificate.OpenPGPComponentSignature(sig, issuer, identity));
            }
            return list;
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
            List<OpenPGPCertificate.OpenPGPComponentSignature> list = new ArrayList<>();
            while (iterator.hasNext())
            {
                PGPSignature sig = iterator.next();
                // try to find issuer for self-signature
                OpenPGPCertificate.OpenPGPComponentKey issuer = getCertificate()
                        .getSigningKeyFor(sig);

                list.add(new OpenPGPCertificate.OpenPGPComponentSignature(sig, issuer, identity));
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

        @Override
        protected OpenPGPComponentKey getKeyComponent()
        {
            return this;
        }

        /**
         * Return all subkey-binding and -revocation signatures on the subkey.
         *
         * @return subkey signatures
         */
        protected List<OpenPGPComponentSignature> getKeySignatures()
        {
            Iterator<PGPSignature> iterator = rawPubkey.getSignatures();
            List<OpenPGPCertificate.OpenPGPComponentSignature> list = new ArrayList<>();
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
                return currentChain.getHeadLink().getSignature();
            }
            return null;
        }

        @Override
        protected OpenPGPComponentKey getKeyComponent()
        {
            return primaryKey;
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
            return getUserId().equals(((OpenPGPUserId) obj).getUserId());
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
        private final List<Link> chainLinks = new ArrayList<>();

        private OpenPGPSignatureChain(Link rootLink)
        {
            this.chainLinks.add(rootLink);
        }

        // copy constructor
        private OpenPGPSignatureChain(OpenPGPSignatureChain copy)
        {
            this.chainLinks.addAll(copy.chainLinks);
        }

        public OpenPGPComponentSignature getSignature()
        {
            return getHeadLink().getSignature();
        }

        /**
         * Return an NEW instance of the {@link OpenPGPSignatureChain} with the new link appended.
         * @param sig signature
         * @param targetComponent signature target
         * @return new instance
         */
        public OpenPGPSignatureChain plus(OpenPGPComponentSignature sig,
                                          OpenPGPCertificateComponent targetComponent)
        {
            if (getHeadKey() != sig.getIssuerComponent())
            {
                throw new IllegalArgumentException("Chain head is not equal to link issuer.");
            }

            OpenPGPSignatureChain chain = new OpenPGPSignatureChain(this);

            chain.chainLinks.add(Link.create(sig, sig.getIssuerComponent(), targetComponent));

            return chain;
        }

        public static OpenPGPSignatureChain direct(OpenPGPComponentSignature sig,
                                                   OpenPGPComponentKey issuer,
                                                   OpenPGPCertificateComponent targetComponent)
        {
            return new OpenPGPSignatureChain(Link.create(sig, issuer, targetComponent));
        }

        public Link getRootLink()
        {
            return chainLinks.get(0);
        }

        public OpenPGPComponentKey getRootKey()
        {
            return getRootLink().issuer;
        }

        public Link getHeadLink()
        {
            return chainLinks.get(chainLinks.size() - 1);
        }

        public OpenPGPComponentKey getHeadKey()
        {
            return getHeadLink().signature.getTargetKeyComponent();
        }

        public boolean isCertification()
        {
            for (Link link : chainLinks)
            {
                if (link instanceof Revocation)
                {
                    return false;
                }
            }
            return true;
        }

        public boolean isRevocation()
        {
            for (Link link : chainLinks)
            {
                if (link instanceof Revocation)
                {
                    return true;
                }
            }
            return false;
        }

        public boolean isHardRevocation()
        {
            for (Link link : chainLinks)
            {
                if (link.signature.signature.isHardRevocation())
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
            // Find most recent chain link
            return chainLinks.stream()
                    .map(it -> it.signature)
                    .max(Comparator.comparing(OpenPGPComponentSignature::getCreationTime))
                    .map(OpenPGPComponentSignature::getCreationTime)
                    .orElse(null);
        }

        /**
         * Return the date until which the chain link is valid.
         * This is the earliest expiration time of any signature in the chain.
         *
         * @return earliest expiration time
         */
        public Date getUntil()
        {
            Date soonestExpiration = null;
            for (Link link : chainLinks)
            {
                Date until = link.until();
                if (until != null)
                {
                    soonestExpiration = (soonestExpiration == null) ? until :
                            (until.before(soonestExpiration) ? until : soonestExpiration);
                }
            }
            return soonestExpiration;
        }

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

        public boolean isValid()
                throws PGPSignatureException
        {
            OpenPGPComponentKey rootKey = getRootKey();
            if (rootKey == null)
            {
                throw new MissingIssuerCertException(getRootLink().signature, "Missing issuer certificate.");
            }
            OpenPGPCertificate cert = rootKey.getCertificate();
            return isValid(cert.implementation.pgpContentVerifierBuilderProvider(), cert.policy);
        }

        public boolean isValid(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider, OpenPGPPolicy policy)
                throws PGPSignatureException
        {
            boolean correct = true;
            for (Link link : chainLinks)
            {
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
            for (Link link : chainLinks)
            {
                b.append("  ").append(link.toString()).append("\n");
            }
            return b.toString();
        }

        @Override
        public int compareTo(OpenPGPSignatureChain other)
        {
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

            compare = -getHeadLink().since().compareTo(other.getHeadLink().since());
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
            protected final OpenPGPComponentKey issuer;
            protected final OpenPGPCertificateComponent target;

            public Link(OpenPGPComponentSignature signature,
                        OpenPGPComponentKey issuer,
                        OpenPGPCertificateComponent target)
            {
                this.signature = signature;
                this.issuer = issuer;
                this.target = target;
            }

            public Date since()
            {
                return signature.getCreationTime();
            }

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
                                getSignature().getTargetKeyComponent(),
                                getSignature().getIssuer());
                        return backSig.getExpirationTime();
                    }
                    return null;
                }
                catch (PGPException e)
                {
                    return null;
                }
            }

            public boolean verify(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider,
                                  OpenPGPPolicy policy)
                    throws PGPSignatureException
            {
                signature.verify(contentVerifierBuilderProvider, policy);
                return true;
            }

            @Override
            public String toString()
            {
                return signature.toString();
            }

            public static Link create(OpenPGPComponentSignature signature,
                                      OpenPGPComponentKey issuer,
                                      OpenPGPCertificateComponent target)
            {
                if (signature.isRevocation())
                {
                    return new Revocation(signature, issuer, target);
                }
                else
                {
                    return new Certification(signature, issuer, target);
                }
            }

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
             * @param issuer key that issued the certification.
             *               Is nullable (e.g. for 3rd-party sigs where the cert is not available)
             * @param target signed certificate component
             */
            public Certification(OpenPGPComponentSignature signature,
                                 OpenPGPComponentKey issuer,
                                 OpenPGPCertificateComponent target)
            {
                super(signature, issuer, target);
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
             * @param issuer key that issued the revocation.
             *               Is nullable (e.g. for 3rd-party sigs where the cert is not available)
             * @param target revoked certification component
             */
            public Revocation(OpenPGPComponentSignature signature,
                              OpenPGPComponentKey issuer,
                              OpenPGPCertificateComponent target)
            {
                super(signature, issuer, target);
            }

            @Override
            public Date since()
            {
                if (signature.signature.isHardRevocation())
                {
                    return new Date(0L);
                }
                return super.since();
            }

            @Override
            public Date until()
            {
                if (signature.signature.isHardRevocation())
                {
                    return new Date(Long.MAX_VALUE);
                }
                return super.until();
            }
        }
    }

    /**
     * Collection of multiple {@link OpenPGPSignatureChain} objects.
     */
    public static class OpenPGPSignatureChains implements Iterable<OpenPGPSignatureChain>
    {
        private final OpenPGPCertificateComponent targetComponent;
        private final Set<OpenPGPSignatureChain> chains = new TreeSet<>();

        public OpenPGPSignatureChains(OpenPGPCertificateComponent component)
        {
            this.targetComponent = component;
        }

        /**
         * Add a single chain to the collection.
         * @param chain chain
         */
        public void add(OpenPGPSignatureChain chain)
        {
            this.chains.add(chain);
        }

        public void addAll(OpenPGPSignatureChains otherChains)
        {
            this.chains.addAll(otherChains.chains);
        }

        public boolean isEmpty()
        {
            return chains.isEmpty();
        }

        /**
         * Return a positive certification chain for the component for the given evaluationTime.
         * @param evaluationTime time for which validity of the {@link OpenPGPCertificateComponent} is checked.
         * @return positive certification chain or null
         */
        public OpenPGPSignatureChain getCertificationAt(Date evaluationTime)
        {
            for (OpenPGPSignatureChain chain : chains)
            {
                boolean isEffective = chain.isEffectiveAt(evaluationTime);
                boolean isCertification = chain.isCertification();
                if (isEffective && isCertification)
                {
                    return chain;
                }
            }
            return null;
        }

        public OpenPGPSignatureChains getChainsAt(Date evaluationTime)
        {
            OpenPGPSignatureChains effectiveChains = new OpenPGPSignatureChains(targetComponent);
            for (OpenPGPSignatureChain chain : chains)
            {
                if (chain.isEffectiveAt(evaluationTime))
                {
                    effectiveChains.add(chain);
                }
            }
            return effectiveChains;
        }

        /**
         * Return a negative certification chain for the component for the given evaluationTime.
         * @param evaluationTime time for which revocation-ness of the {@link OpenPGPCertificateComponent} is checked.
         * @return negative certification chain or null
         */
        public OpenPGPSignatureChain getRevocationAt(Date evaluationTime)
        {
            for (OpenPGPSignatureChain chain : chains)
            {
                if (!chain.isRevocation())
                {
                    continue;
                }

                if (chain.isEffectiveAt(evaluationTime))
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
            for (OpenPGPSignatureChain chain : chains)
            {
                b.append(chain.toString());
            }
            return b.toString();
        }

        public OpenPGPSignatureChains fromOrigin(OpenPGPComponentKey root)
        {
            OpenPGPSignatureChains chainsFromRoot = new OpenPGPSignatureChains(root);
            for (OpenPGPSignatureChain chain : chains)
            {
                OpenPGPComponentKey chainRoot = chain.getRootKey();
                if (chainRoot == root)
                {
                    chainsFromRoot.add(chain);
                }
            }
            return chainsFromRoot;
        }

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
}
