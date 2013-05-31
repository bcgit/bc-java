package org.bouncycastle.jce.provider.test;

import java.security.Security;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

abstract class JceTestUtil
{
    private JceTestUtil()
    {
    }

    static String[] getRegisteredAlgorithms(String prefix, String[] exclusionPatterns)
    {
        final BouncyCastleProvider prov = (BouncyCastleProvider)Security.getProvider("BC");

        List matches = new ArrayList();
        Enumeration algos = prov.keys();
        while (algos.hasMoreElements())
        {
            String algo = (String)algos.nextElement();
            if (!algo.startsWith(prefix))
            {
                continue;
            }
            String algoName = algo.substring(prefix.length());
            if (!isExcluded(algoName, exclusionPatterns))
            {
                matches.add(algoName);
            }
        }
        return (String[])matches.toArray(new String[matches.size()]);
    }

    private static boolean isExcluded(String algoName, String[] exclusionPatterns)
    {
        for (int i = 0; i < exclusionPatterns.length; i++)
        {
            if (algoName.contains(exclusionPatterns[i]))
            {
                return true;
            }
        }
        return false;
    }
}
