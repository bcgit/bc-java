package org.bouncycastle.openpgp.api;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;

public abstract class OpenPGPEncryptionNegotiator
{
    /**
     * Negotiate encryption mode and algorithms.
     *
     * @param configuration message generator configuration
     * @return negotiated encryption mode and algorithms
     */
    public abstract MessageEncryptionMechanism negotiateEncryption(OpenPGPMessageGenerator configuration);

    static PreferredAEADCiphersuites negotiateAEADCiphersuite(List<OpenPGPCertificate> certificates, OpenPGPPolicy policy)
    {
        return new PreferredAEADCiphersuites(false, new PreferredAEADCiphersuites.Combination[]{
            bestAEADCiphersuiteByWeight(certificates, policy)
        });
    }

    /**
     * Return true, if all recipient {@link OpenPGPCertificate certificates} contain at least one subkey that supports
     * {@link Features#FEATURE_SEIPD_V2}.
     *
     * @param certificates certificates
     * @return true if all certificates support the feature, false otherwise
     */
    static boolean allRecipientsSupportSeipd2(List<OpenPGPCertificate> certificates)
    {
        return allRecipientsSupportEncryptionFeature(certificates, Features.FEATURE_SEIPD_V2);
    }

    static boolean allRecipientsSupportLibrePGPOED(List<OpenPGPCertificate> certificates)
    {
        return allRecipientsSupportEncryptionFeature(certificates, Features.FEATURE_AEAD_ENCRYPTED_DATA);
    }

    static boolean allRecipientsSupportEncryptionFeature(List<OpenPGPCertificate> certificates, byte feature)
    {
        for (Iterator it = certificates.iterator(); it.hasNext(); )
        {
            List<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = ((OpenPGPCertificate)it.next()).getEncryptionKeys();
            if (encryptionKeys.isEmpty())
            {
                continue;
            }

            boolean recipientHasSupport = false;
            for (Iterator ckIt = encryptionKeys.iterator(); ckIt.hasNext(); )
            {
                Features features = ((OpenPGPCertificate.OpenPGPComponentKey)ckIt.next()).getFeatures();
                if (features != null && features.supportsFeature(feature))
                {
                    recipientHasSupport = true;
                    break;
                }
            }

            if (!recipientHasSupport)
            {
                return false;
            }
        }
        return true;
    }

    public static PreferredAEADCiphersuites.Combination bestAEADCiphersuiteByWeight(
        Collection<OpenPGPCertificate> certificates, OpenPGPPolicy policy)
    {
        return processCertificates(
            certificates,
            policy,
            new KeyProcessor<PreferredAEADCiphersuites, PreferredAEADCiphersuites.Combination>()
            {
                public boolean processKey(OpenPGPCertificate.OpenPGPComponentKey key, Map<OpenPGPCertificate.OpenPGPComponentKey, PreferredAEADCiphersuites> capableKeys)
                {
                    Features features = key.getFeatures();
                    if (features != null && features.supportsSEIPDv2())
                    {
                        PreferredAEADCiphersuites prefs = key.getAEADCipherSuitePreferences();
                        if (prefs != null)
                        {
                            capableKeys.put(key, prefs);
                            return true;
                        }
                    }
                    return false;
                }

                public List<PreferredAEADCiphersuites.Combination> getAlgorithms(PreferredAEADCiphersuites prefs, OpenPGPPolicy policy)
                {
                    // Weigh the preferences descending by index: w(p_i) = 1/(i+1)
                    // This way, combinations with a smaller index have a higher weight than combinations with larger index.
                    // Additionally, we divide this weight by the number of capable subkeys per cert in order to
                    //  prevent a certificate with many capable subkeys from outvoting other certificates
                    List<PreferredAEADCiphersuites.Combination> result = new ArrayList<PreferredAEADCiphersuites.Combination>();
                    for (PreferredAEADCiphersuites.Combination c : prefs.getAlgorithms())
                    {
                        if (c.getSymmetricAlgorithm() != SymmetricKeyAlgorithmTags.NULL
                            && policy.isAcceptableSymmetricKeyAlgorithm(c.getSymmetricAlgorithm()))
                        {
                            result.add(c);
                        }
                    }
                    return result;
                }
            },
            PreferredAEADCiphersuites.DEFAULT().getAlgorithms()[0]
        );
    }

    static int bestSymmetricKeyAlgorithmByWeight(
        Collection<OpenPGPCertificate> certificates,
        OpenPGPPolicy policy)
    {
        return processCertificates(
            certificates,
            policy,
            new KeyProcessor<PreferredAlgorithms, Integer>()
            {
                @Override
                public boolean processKey(OpenPGPCertificate.OpenPGPComponentKey key,
                                          Map<OpenPGPCertificate.OpenPGPComponentKey, PreferredAlgorithms> capableKeys)
                {
                    Features features = key.getFeatures();
                    if (features != null && features.supportsModificationDetection())
                    {
                        PreferredAlgorithms prefs = key.getSymmetricCipherPreferences();
                        if (prefs != null)
                        {
                            capableKeys.put(key, prefs);
                            return true;
                        }
                    }
                    return false;
                }

                @Override
                public List<Integer> getAlgorithms(PreferredAlgorithms preferences, OpenPGPPolicy policy)
                {
                    // Weigh the preferences descending by index: w(p_i) = 1/(i+1)
                    // This way, combinations with a smaller index have a higher weight than combinations with larger index.
                    // Additionally, we divide this weight by the number of capable subkeys per cert in order to
                    //  prevent a certificate with many capable subkeys from outvoting other certificates
                    List<Integer> result = new ArrayList<Integer>();
                    int[] prefs = preferences.getPreferences();
                    for (int i = 0; i < prefs.length; i++)
                    {
                        int alg = prefs[i];
                        if (alg != SymmetricKeyAlgorithmTags.NULL &&
                            policy.isAcceptableSymmetricKeyAlgorithm(alg))
                        {
                            result.add(alg);
                        }
                    }
                    return result;
                }
            },
            SymmetricKeyAlgorithmTags.AES_128 // Default value
        );
    }

    static int bestOEDEncryptionModeByWeight(Collection<OpenPGPCertificate> certificates,
                                             final OpenPGPPolicy policy)
    {
        return processCertificates(
            certificates,
            policy,
            new KeyProcessor<PreferredAlgorithms, Integer>()
            {
                @Override
                public boolean processKey(OpenPGPCertificate.OpenPGPComponentKey key,
                                          Map<OpenPGPCertificate.OpenPGPComponentKey, PreferredAlgorithms> capableKeys)
                {
                    // Only consider encryption keys capable of OED
                    Features features = key.getFeatures();
                    if (features != null && features.supportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA))
                    {
                        PreferredAlgorithms prefs = key.getSymmetricCipherPreferences();
                        if (prefs != null)
                        {
                            capableKeys.put(key, prefs);
                            return true;
                        }
                    }
                    return false;
                }

                @Override
                public List<Integer> getAlgorithms(PreferredAlgorithms preferences, OpenPGPPolicy policy)
                {
                    // Count the keys symmetric key preferences (that can be used with OED) and update the weight map

                    List<Integer> result = new ArrayList<Integer>();
                    int[] prefs = preferences.getPreferences();
                    for (int i = 0; i < prefs.length; i++)
                    {
                        int alg = prefs[i];
                        if (isOEDCompatible(alg) &&
                            policy.isAcceptableSymmetricKeyAlgorithm(alg))
                        {
                            result.add(alg);
                        }
                    }
                    return result;
                }

                private boolean isOEDCompatible(int alg)
                {
                    switch (alg)
                    {
                    case SymmetricKeyAlgorithmTags.AES_128:
                    case SymmetricKeyAlgorithmTags.AES_192:
                    case SymmetricKeyAlgorithmTags.AES_256:
                    case SymmetricKeyAlgorithmTags.CAMELLIA_128:
                    case SymmetricKeyAlgorithmTags.CAMELLIA_192:
                    case SymmetricKeyAlgorithmTags.CAMELLIA_256:
                        return true;
                    default:
                        return false;
                    }
                }
            },
            SymmetricKeyAlgorithmTags.AES_128 // Default value
        );
    }

    private interface KeyProcessor<T, R>
    {
        /**
         * Process a certificate's encryption key and return true to include it
         */
        boolean processKey(OpenPGPCertificate.OpenPGPComponentKey key, Map<OpenPGPCertificate.OpenPGPComponentKey, T> capableKeys);

        /**
         * Process preferences and return algorithms to consider
         */
        List<R> getAlgorithms(T preferences, OpenPGPPolicy policy);
    }

    private static <T, R> R processCertificates(
        Collection<OpenPGPCertificate> certificates,
        OpenPGPPolicy policy,
        KeyProcessor<T, R> keyProcessor,
        R defaultResult)
    {
        Map<R, Float> weights = new HashMap<R, Float>();

        // Go through all certificate's capable subkeys
        for (Iterator<OpenPGPCertificate> it = certificates.iterator(); it.hasNext(); )
        {
            List<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = it.next().getEncryptionKeys();
            if (encryptionKeys.isEmpty())
            {
                continue;
            }

            // Only consider encryption keys capable of SEIPDv1/OED
            Map<OpenPGPCertificate.OpenPGPComponentKey, T> capableKeys = new HashMap<OpenPGPCertificate.OpenPGPComponentKey, T>();
            for (Iterator<OpenPGPCertificate.OpenPGPComponentKey> ckIt = encryptionKeys.iterator(); ckIt.hasNext(); )
            {
                keyProcessor.processKey(ckIt.next(), capableKeys);
            }

            // Count the keys [AEAD preferences | symmetric key preferences (that can be used with OED)]
            // and update the weight map
            for (Iterator<OpenPGPCertificate.OpenPGPComponentKey> ckIt = capableKeys.keySet().iterator(); ckIt.hasNext(); )
            {
                T prefs = capableKeys.get(ckIt.next());
                List<R> algorithms = keyProcessor.getAlgorithms(prefs, policy);
                for (int i = 0; i < algorithms.size(); i++)
                {
                    R c = algorithms.get(i);
                    float current = weights.containsKey(c) ? weights.get(c) : 0;
                    weights.put(c, current + (1f / (i + 1)) / capableKeys.size());
                }
            }
        }

        R maxKey = defaultResult;
        float maxWeight = -1;
        // Select the entry with the highest weight
        for (Iterator<Map.Entry<R, Float>> it = weights.entrySet().iterator(); it.hasNext(); )
        {
            Map.Entry<R, Float> entry = it.next();
            if (entry.getValue() > maxWeight)
            {
                maxWeight = entry.getValue();
                maxKey = entry.getKey();
            }
        }
        return maxKey;
    }
}