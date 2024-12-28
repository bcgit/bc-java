package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public interface OpenPGPEncryptionNegotiator
{
    /**
     * Negotiate encryption mode and algorithms.
     *
     * @param configuration message generator configuration
     * @return negotiated encryption mode and algorithms
     */
    MessageEncryptionMechanism negotiateEncryption(OpenPGPMessageGenerator.Configuration configuration);

    static PreferredAEADCiphersuites negotiateAEADCiphersuite(List<OpenPGPCertificate> certificates)
    {
        return new PreferredAEADCiphersuites(false, new PreferredAEADCiphersuites.Combination[]{
                bestAEADCiphersuiteByWeight(certificates)
        });
    }

    /**
     * Return true, if all recipient {@link OpenPGPCertificate certificates} contain at least one subkey that supports
     * {@link Features#FEATURE_SEIPD_V2}.
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
        for (OpenPGPCertificate recipient : certificates)
        {
            List<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = recipient.getEncryptionKeys();
            if (encryptionKeys.isEmpty())
            {
                continue;
            }

            boolean recipientHasSupport = false;
            for (OpenPGPCertificate.OpenPGPComponentKey subkey : encryptionKeys)
            {
                Features features = subkey.getFeatures();
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

    static PreferredAEADCiphersuites.Combination bestAEADCiphersuiteByWeight(Collection<OpenPGPCertificate> certificates)
    {
        // Keep track of combinations, assigning a weight
        Map<PreferredAEADCiphersuites.Combination, Float> weights = new HashMap<>();

        // Go through all certificate's capable subkeys
        for (OpenPGPCertificate certificate : certificates)
        {
            List<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = certificate.getEncryptionKeys();
            if (encryptionKeys.isEmpty())
            {
                continue;
            }

            // Only consider encryption keys capable of AEAD
            Map<OpenPGPCertificate.OpenPGPComponentKey, PreferredAEADCiphersuites> capableKeys = new HashMap<>();
            for (OpenPGPCertificate.OpenPGPComponentKey subkey : encryptionKeys)
            {
                Features features = subkey.getFeatures();
                if (features == null || !features.supportsSEIPDv2())
                {
                    continue;
                }

                PreferredAEADCiphersuites preferences = subkey.getAEADCipherSuitePreferences();
                if (preferences == null)
                {
                    continue;
                }
                capableKeys.put(subkey, preferences);
            }

            // Count the keys AEAD preferences and update the weight map
            for (OpenPGPCertificate.OpenPGPComponentKey subkey : capableKeys.keySet())
            {
                PreferredAEADCiphersuites preferences = capableKeys.get(subkey);

                // Weigh the preferences descending by index: w(p_i) = 1/(i+1)
                // This way, combinations with a smaller index have a higher weight than combinations with larger index.
                // Additionally, we divide this weight by the number of capable subkeys per cert in order to
                //  prevent a certificate with many capable subkeys from outvoting other certificates
                List<PreferredAEADCiphersuites.Combination> algorithms =
                        Arrays.stream(preferences.getAlgorithms())
                                .filter(it -> it.getSymmetricAlgorithm() != SymmetricKeyAlgorithmTags.NULL)
                                .collect(Collectors.toList());
                for (int i = 0; i < algorithms.size(); i++)
                {
                    PreferredAEADCiphersuites.Combination c = algorithms.get(i);
                    float currentWeight = weights.getOrDefault(c, 0f);
                    float addedWeight = (1f / (i + 1)) / capableKeys.size();
                    weights.put(c, currentWeight + addedWeight);
                }
            }
        }

        // Select the entry with the highest weight
        Map.Entry<PreferredAEADCiphersuites.Combination, Float> maxEntry = null;
        for (Map.Entry<PreferredAEADCiphersuites.Combination, Float> entry : weights.entrySet())
        {
            if (maxEntry == null || entry.getValue() > maxEntry.getValue())
            {
                maxEntry = entry;
            }
        }

        if (maxEntry != null)
        {
            return maxEntry.getKey();
        }

        // else, return default combination
        return PreferredAEADCiphersuites.DEFAULT().getAlgorithms()[0];
    }

    static int bestSymmetricKeyAlgorithmByWeight(Collection<OpenPGPCertificate> certificates)
    {
        Map<Integer, Float> weights = new HashMap<>();

        // Go through all certificate's capable subkeys
        for (OpenPGPCertificate certificate : certificates)
        {
            List<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = certificate.getEncryptionKeys();
            if (encryptionKeys.isEmpty())
            {
                continue;
            }

            // Only consider encryption keys capable of SEIPDv1
            Map<OpenPGPCertificate.OpenPGPComponentKey, PreferredAlgorithms> capableKeys = new HashMap<>();
            for (OpenPGPCertificate.OpenPGPComponentKey subkey : encryptionKeys)
            {
                Features features = subkey.getFeatures();
                if (features == null || !features.supportsModificationDetection())
                {
                    continue;
                }

                PreferredAlgorithms preferences = subkey.getSymmetricCipherPreferences();
                if (preferences == null)
                {
                    continue;
                }
                capableKeys.put(subkey, preferences);
            }

            // Count the keys AEAD preferences and update the weight map
            for (OpenPGPCertificate.OpenPGPComponentKey subkey : capableKeys.keySet())
            {
                PreferredAlgorithms preferences = capableKeys.get(subkey);

                // Weigh the preferences descending by index: w(p_i) = 1/(i+1)
                // This way, combinations with a smaller index have a higher weight than combinations with larger index.
                // Additionally, we divide this weight by the number of capable subkeys per cert in order to
                //  prevent a certificate with many capable subkeys from outvoting other certificates
                int[] algorithms = Arrays.stream(preferences.getPreferences())
                        .filter(it -> it != SymmetricKeyAlgorithmTags.NULL)
                        .toArray();

                for (int i = 0; i < algorithms.length; i++)
                {
                    int a = algorithms[i];
                    float currentWeight = weights.getOrDefault(a, 0f);
                    float addedWeight = (1f / (i + 1)) / capableKeys.size();
                    weights.put(a, currentWeight + addedWeight);
                }
            }
        }

        // Select the entry with the highest weight
        Map.Entry<Integer, Float> maxEntry = null;
        for (Map.Entry<Integer, Float> entry : weights.entrySet())
        {
            if (maxEntry == null || entry.getValue() > maxEntry.getValue())
            {
                maxEntry = entry;
            }
        }

        if (maxEntry != null)
        {
            return maxEntry.getKey();
        }

        // else, return default combination
        return SymmetricKeyAlgorithmTags.AES_128;
    }

    static int bestOEDEncryptionModeByWeight(Collection<OpenPGPCertificate> certificates)
    {
        Map<Integer, Float> weights = new HashMap<>();

        // Go through all certificate's capable subkeys
        for (OpenPGPCertificate certificate : certificates)
        {
            List<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = certificate.getEncryptionKeys();
            if (encryptionKeys.isEmpty())
            {
                continue;
            }

            // Only consider encryption keys capable of OED
            Map<OpenPGPCertificate.OpenPGPComponentKey, PreferredAlgorithms> capableKeys = new HashMap<>();
            for (OpenPGPCertificate.OpenPGPComponentKey subkey : encryptionKeys)
            {
                Features features = subkey.getFeatures();
                if (features == null || !features.supportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA))
                {
                    continue;
                }

                PreferredAlgorithms preferences = subkey.getSymmetricCipherPreferences();
                if (preferences == null)
                {
                    continue;
                }
                capableKeys.put(subkey, preferences);
            }

            // Count the keys symmetric key preferences (that can be used with OED) and update the weight map
            for (OpenPGPCertificate.OpenPGPComponentKey subkey : capableKeys.keySet())
            {
                PreferredAlgorithms preferences = capableKeys.get(subkey);
                int[] algorithms = Arrays.stream(preferences.getPreferences())
                        .filter(alg ->
                        {
                            switch (alg) {
                                case SymmetricKeyAlgorithmTags.AES_128:
                                case SymmetricKeyAlgorithmTags.AES_192:
                                case SymmetricKeyAlgorithmTags.AES_256:
                                // case SymmetricKeyAlgorithmTags.TWOFISH:
                                case SymmetricKeyAlgorithmTags.CAMELLIA_128:
                                case SymmetricKeyAlgorithmTags.CAMELLIA_192:
                                case SymmetricKeyAlgorithmTags.CAMELLIA_256:
                                    return true;
                                default:
                                    return false;
                            }
                        })
                        .toArray();

                // Weigh the preferences descending by index: w(p_i) = 1/(i+1)
                // This way, combinations with a smaller index have a higher weight than combinations with larger index.
                // Additionally, we divide this weight by the number of capable subkeys per cert in order to
                //  prevent a certificate with many capable subkeys from outvoting other certificates
                for (int i = 0; i < algorithms.length; i++)
                {
                    int a = algorithms[i];
                    float currentWeight = weights.getOrDefault(a, 0f);
                    float addedWeight = (1f / (i + 1)) / capableKeys.size();
                    weights.put(a, currentWeight + addedWeight);
                }
            }
        }

        // Select the entry with the highest weight
        Map.Entry<Integer, Float> maxEntry = null;
        for (Map.Entry<Integer, Float> entry : weights.entrySet())
        {
            if (maxEntry == null || entry.getValue() > maxEntry.getValue())
            {
                maxEntry = entry;
            }
        }

        if (maxEntry != null)
        {
            return maxEntry.getKey();
        }

        // else, return default combination
        return SymmetricKeyAlgorithmTags.AES_128;
    }
}
