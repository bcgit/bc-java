package org.bouncycastle.jsse.provider;

import java.util.Arrays;
import java.util.Locale;
import java.util.Vector;
import java.util.logging.Logger;

import org.bouncycastle.tls.NamedGroup;

abstract class SupportedGroups
{
    private static Logger LOG = Logger.getLogger(SupportedGroups.class.getName());

    private static final String PROPERTY_NAME = "jdk.tls.namedGroups";

    private static final int[] provJdkTlsNamedGroups = getJdkTlsNamedGroups();
    private static final int[] defaultNamedGroups = new int[]{
        NamedGroup.secp256r1,
        NamedGroup.secp384r1,
        NamedGroup.secp521r1,
        NamedGroup.ffdhe2048,
        NamedGroup.ffdhe3072,
        NamedGroup.ffdhe4096,
    };

    static int[] getJdkTlsNamedGroups()
    {
        String prop = PropertyUtils.getStringSystemProperty(PROPERTY_NAME);
        if (prop == null)
        {
            return null;
        }

        String[] entries = JsseUtils.stripQuotes(prop.trim()).toLowerCase(Locale.ENGLISH).split(",");
        int[] result = new int[entries.length];
        int count = 0;
        for (String entry : entries)
        {
            String name = entry.trim();
            if (name.length() < 1)
                continue;

            int namedGroup = NamedGroup.getByName(name.trim());
            if (namedGroup < 0)
            {
                LOG.warning("'" + PROPERTY_NAME + "' contains unrecognised NamedGroup: " + name);
            }
            else
            {
                result[count++] = namedGroup;
            }
        }
        if (count < result.length)
        {
            result = Arrays.copyOfRange(result, 0, count);
        }
        if (result.length < 1)
        {
            LOG.severe("'" + PROPERTY_NAME + "' contains no recognised NamedGroup values");
        }
        return result;
    }

    static Vector getClientSupportedGroups(boolean isFips, boolean offeringDH, boolean offeringEC)
    {
        int[] namedGroups = provJdkTlsNamedGroups != null ? provJdkTlsNamedGroups : defaultNamedGroups;

        Vector result = new Vector();
        for (int namedGroup : namedGroups)
        {
            if ((offeringDH && NamedGroup.refersToASpecificFiniteField(namedGroup))
                || (offeringEC && NamedGroup.refersToASpecificCurve(namedGroup)))
            {
                if (!isFips || FipsUtils.isFipsNamedGroup(namedGroup))
                {
                    result.addElement(namedGroup);
                }
            }
        }
        return result;
    }
}
