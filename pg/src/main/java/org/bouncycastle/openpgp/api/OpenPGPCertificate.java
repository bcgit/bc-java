package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.FingerprintUtil;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.api.exception.IncorrectPGPSignatureException;
import org.bouncycastle.openpgp.api.exception.MissingIssuerCertException;
import org.bouncycastle.openpgp.api.util.UTCUtil;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
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
    private final OpenPGPImplementation implementation;

    private final PGPKeyRing keyRing;

    private final OpenPGPPrimaryKey primaryKey;
    private final Map<KeyIdentifier, OpenPGPSubkey> subkeys;

    // Note: get() needs to be accessed with OpenPGPCertificateComponent.getPublicComponent() to ensure
    //  proper functionality with secret key components.
    private final Map<OpenPGPCertificateComponent, OpenPGPSignatureChains> componentSignatureChains;

    public OpenPGPCertificate(PGPKeyRing keyRing)
    {
        this(keyRing, OpenPGPImplementation.getInstance());
    }

    /**
     * Instantiate an {@link OpenPGPCertificate} from a parsed {@link PGPPublicKeyRing}.
     *
     * @param keyRing public key ring
     * @param implementation OpenPGP implementation
     */
    public OpenPGPCertificate(PGPKeyRing keyRing, OpenPGPImplementation implementation)
    {
        this.implementation = implementation;

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

    /**
     * Parse an {@link OpenPGPCertificate} (or {@link OpenPGPKey}) from its ASCII armored representation.
     * @param armor ASCII armored key or certificate
     * @return certificate or key
     * @throws IOException
     */
    public static OpenPGPCertificate fromAsciiArmor(String armor)
            throws IOException
    {
        return fromAsciiArmor(armor, OpenPGPImplementation.getInstance());
    }

    /**
     * Parse an {@link OpenPGPCertificate} (or {@link OpenPGPKey}) from its ASCII armored representation.
     * @param armor ASCII armored key or certificate
     * @param implementation OpenPGP implementation
     * @return certificate or key
     * @throws IOException
     */
    public static OpenPGPCertificate fromAsciiArmor(
            String armor,
            OpenPGPImplementation implementation)
            throws IOException
    {
        return fromBytes(
                armor.getBytes(StandardCharsets.UTF_8),
                implementation);
    }

    public static OpenPGPCertificate fromBytes(
            byte[] bytes,
            OpenPGPImplementation implementation)
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        InputStream decoderStream = PGPUtil.getDecoderStream(bIn);
        BCPGInputStream pIn = BCPGInputStream.wrap(decoderStream);
        PGPObjectFactory objectFactory = implementation.pgpObjectFactory(pIn);
        Object object = objectFactory.nextObject();

        // TODO: Is it dangerous, if we don't explicitly fail upon encountering secret key material here?
        //  Could it lead to a situation where we need to be cautious with the certificate API design to
        //  prevent the user from doing dangerous things like accidentally publishing their private key?

        if (object instanceof PGPSecretKeyRing)
        {
            return new OpenPGPKey((PGPSecretKeyRing) object, implementation);
        }
        else if (object instanceof PGPPublicKeyRing)
        {
            return new OpenPGPCertificate((PGPPublicKeyRing) object, implementation);
        }
        else
        {
            throw new IOException("Neither a certificate, nor secret key.");
        }
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

            }

            else if (next instanceof PGPSignatureList)
            {
                // assume there to be primary key (self) signatures
                // TODO: Allow consumption of 3rd-party sigs
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

    public byte[] getFingerprint()
    {
        return primaryKey.getPGPPublicKey().getFingerprint();
    }

    public String getPrettyFingerprint()
    {
        return FingerprintUtil.prettifyFingerprint(getFingerprint());
    }

    public String toAsciiArmoredString()
            throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream.Builder armorBuilder = ArmoredOutputStream.builder()
                .clearHeaders();
        // Add fingerprint comment
        splitMultilineComment(armorBuilder, getPrettyFingerprint());

        // Add user-id comments
        for (OpenPGPUserId userId : getPrimaryKey().getUserIDs())
        {
            ellipsizedComment(armorBuilder, userId.getUserId());
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

    private void splitMultilineComment(ArmoredOutputStream.Builder armorBuilder, String comment)
    {
        int availableCommentCharsPerLine = 64 - "Comment: ".length(); // ASCII armor width - header len

        comment = comment.trim();

        while (comment.length() > availableCommentCharsPerLine)
        {
            // split comment into multiple lines
            armorBuilder.addComment(comment.substring(0, availableCommentCharsPerLine));
            comment = comment.substring(availableCommentCharsPerLine).trim();
        }

        if (!comment.isEmpty())
        {
            armorBuilder.addComment(comment);
        }
    }

    private void ellipsizedComment(ArmoredOutputStream.Builder armorBuilder, String comment)
    {
        int availableCommentCharsPerLine = 64 - "Comment: ".length(); // ASCII armor width - header len
        comment = comment.trim();

        if (comment.length() > availableCommentCharsPerLine)
        {
            comment = comment.substring(0, availableCommentCharsPerLine - 1) + '…';
        }
        armorBuilder.addComment(comment);
    }

    protected List<String> fingerprintComments()
    {
        // TODO: Implement slicing in ArmoredOutputStream.Builder instead?
        String prettyPrinted = FingerprintUtil.prettifyFingerprint(getFingerprint());

        int availableCommentCharsPerLine = 64 - "Comment: ".length(); // ASCII armor width - header len
        List<String> slices = new ArrayList<>();

        while (prettyPrinted.length() > availableCommentCharsPerLine)
        {
            slices.add(prettyPrinted.substring(0, availableCommentCharsPerLine));
            prettyPrinted = prettyPrinted.substring(availableCommentCharsPerLine).trim();
        }
        slices.add(prettyPrinted);
        return slices;
    }

    private OpenPGPSignatureChain getSignatureChainFor(OpenPGPCertificateComponent component,
                                                       OpenPGPComponentKey origin,
                                                       Date evaluationDate)
    {
        // Check if there are signatures at all for the component
        OpenPGPSignatureChains chainsForComponent = getAllSignatureChainsFor(component);
        if (component == getPrimaryKey() && chainsForComponent.isEmpty())
        {
            // If cert has no direct-key signatures, consider UID bindings instead
            // TODO: Only consider current primary user id?
            for (OpenPGPIdentityComponent identity : getPrimaryKey().identityComponents)
            {
                chainsForComponent.addAll(getAllSignatureChainsFor(identity));
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
        return componentSignatureChains.get(component.getPublicComponent());
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
        try
        {
            OpenPGPSignatureChain chain = getSignatureChainFor(component, root, evaluationTime);
            if (chain == null)
            {
                // Component is not bound at all
                return false;
            }

            // Chain needs to be valid (signatures correct)
            if (chain.isValid(implementation.pgpContentVerifierBuilderProvider()))
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

    public List<OpenPGPIdentityComponent> getIdentities()
    {
        return new ArrayList<>(primaryKey.identityComponents);
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
            return getCertificate().getAllSignatureChainsFor(this);
        }

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

        /**
         * Verify this signature.
         *
         * @param contentVerifierBuilderProvider provider for verifiers
         * @throws PGPSignatureException if the signature cannot be verified successfully
         */
        public void verify(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
                throws PGPSignatureException
        {
            if (issuer == null)
            {
                // No issuer available
                throw new MissingIssuerCertException("Issuer certificate unavailable.");
            }

            sanitize(issuer);

            // Direct-Key signature
            if (target == issuer)
            {
                verifyKeySignature(
                        issuer,
                        issuer,
                        contentVerifierBuilderProvider);
            }

            // Subkey binding signature
            else if (target instanceof OpenPGPSubkey)
            {
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

        public void verifyKeySignature(OpenPGPComponentKey issuer,
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
                else
                {
                    // Subkey Binding Signature
                    isCorrect = signature.verifyCertification(issuer.getPGPPublicKey(), target.getPGPPublicKey());
                }

                if (!isCorrect)
                {
                    throw new IncorrectPGPSignatureException("Key Signature is not correct.");
                }
            }
            catch (PGPException e)
            {
                this.isCorrect = false;
                throw new PGPSignatureException("Key Signature could not be verified.", e);
            }
        }

        public void verifyUserIdSignature(OpenPGPComponentKey issuer,
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
                    throw new IncorrectPGPSignatureException("UserID Signature is not correct.");
                }
            }
            catch (PGPException e)
            {
                this.isCorrect = false;
                throw new PGPSignatureException("UserID Signature could not be verified.", e);
            }
        }

        public void verifyUserAttributeSignature(OpenPGPComponentKey issuer,
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
                    throw new IncorrectPGPSignatureException("UserAttribute Signature is not correct.");
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
         * Return the creation time of this key.
         *
         * @return creation time
         */
        public Date getCreationTime()
        {
            return rawPubkey.getCreationTime();
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

            KeyFlags keyFlags = getKeyFlags(evaluationTime);
            if (keyFlags == null)
            {
                return false;
            }

            int flags = keyFlags.getFlags();
            return (flags & KeyFlags.ENCRYPT_COMMS) == KeyFlags.ENCRYPT_COMMS ||
                    (flags & KeyFlags.ENCRYPT_STORAGE) == KeyFlags.ENCRYPT_STORAGE;
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
            // TODO: Replace with https://github.com/bcgit/bc-java/pull/1857/files#diff-36f593d586240aec2546daad96d16b5debd3463202a3d5d82c0b2694572c8426R14-R30
            int alg = rawPubkey.getAlgorithm();
            if (alg != PublicKeyAlgorithmTags.RSA_GENERAL &&
                    alg != PublicKeyAlgorithmTags.RSA_SIGN &&
                    alg != PublicKeyAlgorithmTags.DSA &&
                    alg != PublicKeyAlgorithmTags.ECDSA &&
                    alg != PublicKeyAlgorithmTags.EDDSA_LEGACY &&
                    alg != PublicKeyAlgorithmTags.Ed25519 &&
                    alg != PublicKeyAlgorithmTags.Ed448)
            {
                // Key is not signing-capable by algorithm
                return false;
            }

            KeyFlags keyFlags = getKeyFlags(evaluationTime);
            if (keyFlags == null)
            {
                return false;
            }

            int flags = keyFlags.getFlags();
            return (flags & KeyFlags.SIGN_DATA) == KeyFlags.SIGN_DATA;
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
            // TODO: Replace with https://github.com/bcgit/bc-java/pull/1857/files#diff-36f593d586240aec2546daad96d16b5debd3463202a3d5d82c0b2694572c8426R14-R30
            int alg = rawPubkey.getAlgorithm();
            if (alg != PublicKeyAlgorithmTags.RSA_GENERAL &&
                    alg != PublicKeyAlgorithmTags.RSA_SIGN &&
                    alg != PublicKeyAlgorithmTags.DSA &&
                    alg != PublicKeyAlgorithmTags.ECDSA &&
                    alg != PublicKeyAlgorithmTags.EDDSA_LEGACY &&
                    alg != PublicKeyAlgorithmTags.Ed25519 &&
                    alg != PublicKeyAlgorithmTags.Ed448)
            {
                // Key is not signing-capable by algorithm
                return false;
            }

            KeyFlags keyFlags = getKeyFlags(evaluationTime);
            if (keyFlags == null)
            {
                return false;
            }

            int flags = keyFlags.getFlags();
            return (flags & KeyFlags.CERTIFY_OTHER) == KeyFlags.CERTIFY_OTHER;
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
            SignatureSubpacket subpacket = getApplyingSubpacket(
                    evaluationTime, SignatureSubpacketTags.KEY_FLAGS);
            if (subpacket != null)
            {
                return (KeyFlags) subpacket;
            }
            return null;
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
            SignatureSubpacket subpacket = getApplyingSubpacket(evaluationTime, SignatureSubpacketTags.FEATURES);
            if (subpacket != null)
            {
                return (Features) subpacket;
            }
            return null;
        }

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
        protected SignatureSubpacket getApplyingSubpacket(Date evaluationTime, int subpacketType)
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
                hashedSubpackets = preferenceBinding.getHeadLink().getSignature().getSignature().getHashedSubPackets();
            }
            // else -> attribute from DK sig is shadowed by SB sig

            // Extract subpacket from hashed area
            return hashedSubpackets.getSubpacket(subpacketType);
        }

        public PreferredAEADCiphersuites getAEADCipherSuitePreferences()
        {
            return getAEADCipherSuitePreferences(new Date());
        }

        public PreferredAEADCiphersuites getAEADCipherSuitePreferences(Date evaluationTime)
        {
            SignatureSubpacket subpacket = getApplyingSubpacket(evaluationTime,
                    SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS);
            if (subpacket != null)
            {
                return (PreferredAEADCiphersuites) subpacket;
            }
            return null;
        }

        public PreferredAlgorithms getSymmetricCipherPreferences()
        {
            return getSymmetricCipherPreferences(new Date());
        }

        public PreferredAlgorithms getSymmetricCipherPreferences(Date evaluationTime)
        {
            SignatureSubpacket subpacket = getApplyingSubpacket(evaluationTime, SignatureSubpacketTags.PREFERRED_SYM_ALGS);
            if (subpacket != null)
            {
                return (PreferredAlgorithms) subpacket;
            }
            return null;
        }

        public PreferredAlgorithms getHashAlgorithmPreferences()
        {
            return getHashAlgorithmPreferences(new Date());
        }

        public PreferredAlgorithms getHashAlgorithmPreferences(Date evaluationTime)
        {
            SignatureSubpacket subpacket = getApplyingSubpacket(evaluationTime, SignatureSubpacketTags.PREFERRED_HASH_ALGS);
            if (subpacket != null)
            {
                return (PreferredAlgorithms) subpacket;
            }
            return null;
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
            return "PrimaryKey[" + Long.toHexString(getKeyIdentifier().getKeyId()).toUpperCase() + "]";
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
        public String toString()
        {
            return "Subkey[" + Long.toHexString(getKeyIdentifier().getKeyId()).toUpperCase() + "]";
        }

        @Override
        public String toDetailString()
        {
            return "Subkey[" + getKeyIdentifier() + "] (" + UTCUtil.format(getCreationTime()) + ")";
        }

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

        public OpenPGPPrimaryKey getPrimaryKey()
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

        public String getUserId()
        {
            return userId;
        }

        @Override
        public String toString()
        {
            return "UserID[" + userId + "]";
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
            return !evaluationDate.before(since) && (until == null || evaluationDate.before(until));
        }

        public boolean isValid()
                throws PGPSignatureException
        {
            return isValid(getRootKey().getCertificate().implementation.pgpContentVerifierBuilderProvider());
        }

        public boolean isValid(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
                throws PGPSignatureException
        {
            boolean correct = true;
            for (Link link : chainLinks)
            {
                if (!link.signature.isTested)
                {
                    link.verify(contentVerifierBuilderProvider);
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

            return -getSince().compareTo(other.getSince());
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
                return signature.getExpirationTime();
            }

            public boolean verify(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
                    throws PGPSignatureException
            {
                signature.verify(contentVerifierBuilderProvider);
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
