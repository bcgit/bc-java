package org.bouncycastle.test.est.examples;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

class SuffixList
{

    static Set<String> loadSuffixes(String file)
        throws Exception
    {
        FileInputStream fin = new FileInputStream(file);
        String line = null;
        BufferedReader bin = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
        ArrayList<String> suffixes = new ArrayList<String>();

        while ((line = bin.readLine()) != null)
        {
            if (line.length() == 0 || (line.startsWith("//") && !line.startsWith("// xn--")))
            {
                continue;
            }

            if (line.startsWith("!"))
            {
                continue;
            }

            line = line.trim();
            if (line.startsWith("// xn--"))
            {
                String[] j = line.split(" ");
                suffixes.add(j[1]);
            }
            else
            {
                suffixes.add(line);
            }
        }

        bin.close();

        for (int t = 0; t < suffixes.size(); t++)
        {
            String j = suffixes.get(t);
            if (j.startsWith("*.")) {
                j = j.substring(2);
            }
            suffixes.set(t, j);
        }

        HashSet<String> set = new HashSet<String>();
        for (String s : suffixes)
        {
            set.add(s);
        }
        return set;
    }
}
