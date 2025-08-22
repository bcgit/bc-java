package org.bouncycastle.jsse.provider;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

class JcaAlgorithmDecomposer
    implements AlgorithmDecomposer
{
    private static final Map<String, String> SHA_DIGEST_MAP = createSHADigestMap();

    private static final Pattern PATTERN = Pattern.compile("with|and|(?<!padd)in", Pattern.CASE_INSENSITIVE);

    static final JcaAlgorithmDecomposer INSTANCE_JCA = new JcaAlgorithmDecomposer();

    public Set<String> decompose(String algorithm)
    {
        Set<String> result = new HashSet<String>();

        if (JsseUtils.isNameSpecified(algorithm))
        {
            implDecompose(result, algorithm);

            if (algorithm.contains("SHA"))
            {
                for (Map.Entry<String, String> entry : SHA_DIGEST_MAP.entrySet())
                {
                    includeBothIfEither(result, entry.getKey(), entry.getValue());
                }
            }
        }

        return result;
    }

    static String decomposeDigestName(String algorithm)
    {
        String result = SHA_DIGEST_MAP.get(algorithm);
        if (result == null)
        {
            result = algorithm;
        }
        return result;
    }

    static Set<String> decomposeName(String algorithm)
    {
        Set<String> result = new HashSet<String>();

        if (JsseUtils.isNameSpecified(algorithm))
        {
            implDecompose(result, algorithm);

            if (algorithm.contains("SHA"))
            {
                for (Map.Entry<String, String> entry : SHA_DIGEST_MAP.entrySet())
                {
                    replaceFirstWithSecond(result, entry.getKey(), entry.getValue());
                }
            }
        }

        return result;
    }

    private static Map<String, String> createSHADigestMap()
    {
        Map<String, String> result = new HashMap<String, String>();
        result.put("SHA-1", "SHA1");
        result.put("SHA-224", "SHA224");
        result.put("SHA-256", "SHA256");
        result.put("SHA-384", "SHA384");
        result.put("SHA-512", "SHA512");
        result.put("SHA-512/224", "SHA512/224");
        result.put("SHA-512/256", "SHA512/256");
        return result;
    }

    private static void implDecompose(Set<String> result, String algorithm)
    {
        for (String section : algorithm.split("/"))
        {
            if (section.length() > 0)
            {
                for (String part : PATTERN.split(section))
                {
                    if (part.length() > 0)
                    {
                        result.add(part);
                    }
                }
            }
        }
    }

    private static void includeBothIfEither(Set<String> elements, String a, String b)
    {
        if (elements.contains(a))
        {
            elements.add(b);
        }
        else if (elements.contains(b))
        {
            elements.add(a);
        }
    }

    private static void replaceFirstWithSecond(Set<String> elements, String a, String b)
    {
        if (elements.remove(a))
        {
            elements.add(b);
        }
    }
}
