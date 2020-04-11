package org.bouncycastle.jsse.provider;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

class JcaAlgorithmDecomposer
    implements AlgorithmDecomposer
{
    private static final Pattern PATTERN = Pattern.compile("with|and|(?<!padd)in", Pattern.CASE_INSENSITIVE);

    static final JcaAlgorithmDecomposer INSTANCE_JCA = new JcaAlgorithmDecomposer();

    public Set<String> decompose(String algorithm)
    {
        if (algorithm.indexOf('/') < 0)
        {
            return Collections.emptySet();
        }

        Set<String> result = new HashSet<String>();

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

        ensureBothIfEither(result, "SHA1", "SHA-1");
        ensureBothIfEither(result, "SHA224", "SHA-224");
        ensureBothIfEither(result, "SHA256", "SHA-256");
        ensureBothIfEither(result, "SHA384", "SHA-384");
        ensureBothIfEither(result, "SHA512", "SHA-512");

        return result;
    }

    private static void ensureBothIfEither(Set<String> elements, String a, String b)
    {
        boolean hasA = elements.contains(a), hasB = elements.contains(b);
        if (hasA ^ hasB)
        {
            elements.add(hasA ? b : a);
        }
    }
}
