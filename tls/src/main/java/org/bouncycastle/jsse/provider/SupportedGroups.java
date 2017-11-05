package org.bouncycastle.jsse.provider;

import java.util.Locale;
import java.util.Vector;
import java.util.logging.Logger;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.crypto.DHStandardGroups;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.util.Arrays;

abstract class SupportedGroups
{
    private static Logger LOG = Logger.getLogger(SupportedGroups.class.getName());

    private static final String PROPERTY_NAME = "jdk.tls.namedGroups";

    private static final int[] provJdkTlsNamedGroups = getJdkTlsNamedGroups();
    private static final int[] defaultClientNamedGroups = new int[]{
        NamedGroup.secp256r1,
        NamedGroup.secp384r1,
        NamedGroup.secp521r1,
        NamedGroup.ffdhe2048,
        NamedGroup.ffdhe3072,
        NamedGroup.ffdhe4096,
    };

    private static int getDefaultCurve(int minimumCurveBits)
    {
        return minimumCurveBits <= 256 ? NamedGroup.secp256r1
            :  minimumCurveBits <= 384 ? NamedGroup.secp384r1
            :  minimumCurveBits <= 521 ? NamedGroup.secp521r1
            :  minimumCurveBits <= 571 ? NamedGroup.sect571r1
            :  -1;
    }

    private static TlsDHConfig getDefaultDHConfig(int minimumFiniteFieldBits)
    {
        return minimumFiniteFieldBits <= 1024 ? new TlsDHConfig(DHStandardGroups.rfc2409_1024)
            :  minimumFiniteFieldBits <= 1536 ? new TlsDHConfig(DHStandardGroups.rfc3526_1536)
            :  TlsDHUtils.createNamedDHConfig(getDefaultFiniteField(minimumFiniteFieldBits));
    }

    private static int getDefaultFiniteField(int minimumFiniteFieldBits)
    {
        return minimumFiniteFieldBits <= 2048 ? NamedGroup.ffdhe2048
            :  minimumFiniteFieldBits <= 3072 ? NamedGroup.ffdhe3072
            :  minimumFiniteFieldBits <= 4096 ? NamedGroup.ffdhe4096
            :  minimumFiniteFieldBits <= 6144 ? NamedGroup.ffdhe6144
            :  minimumFiniteFieldBits <= 8192 ? NamedGroup.ffdhe8192
            :  -1;
    }

    private static int[] getJdkTlsNamedGroups()
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
            result = Arrays.copyOf(result, count);
        }
        if (result.length < 1)
        {
            LOG.severe("'" + PROPERTY_NAME + "' contains no recognised NamedGroup values");
        }
        return result;
    }

    static Vector getClientSupportedGroups(boolean isFips, boolean offeringDH, boolean offeringEC)
    {
        int[] namedGroups = provJdkTlsNamedGroups != null ? provJdkTlsNamedGroups : defaultClientNamedGroups;

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

    static int getServerDefaultCurve(boolean isFips, int minimumCurveBits)
    {
        /*
         * If supported groups wasn't explicitly configured, servers support all available curves.
         */
        int[] serverSupportedGroups = provJdkTlsNamedGroups;

        if (serverSupportedGroups == null)
        {
            if (isFips)
            {
                return FipsUtils.getFipsDefaultCurve(minimumCurveBits);
            }

            return getDefaultCurve(minimumCurveBits);
        }

        for (int namedGroup : serverSupportedGroups)
        {
            if (NamedGroup.getCurveBits(namedGroup) >= minimumCurveBits)
            {
                if (!isFips || FipsUtils.isFipsNamedGroup(namedGroup))
                {
                    return namedGroup;
                }
            }
        }
        
        return -1;
    }

    static TlsDHConfig getServerDefaultDHConfig(boolean isFips, int minimumFiniteFieldBits)
    {
        /*
         * If supported groups wasn't explicitly configured, servers support all available finite fields.
         */
        int[] serverSupportedGroups = provJdkTlsNamedGroups;

        if (serverSupportedGroups == null)
        {
            if (isFips)
            {
                return TlsDHUtils.createNamedDHConfig(FipsUtils.getFipsDefaultFiniteField(minimumFiniteFieldBits));
            }

            return getDefaultDHConfig(minimumFiniteFieldBits);
        }

        for (int namedGroup : serverSupportedGroups)
        {
            if (NamedGroup.getFiniteFieldBits(namedGroup) >= minimumFiniteFieldBits)
            {
                if (!isFips || FipsUtils.isFipsNamedGroup(namedGroup))
                {
                    return new TlsDHConfig(namedGroup);
                }
            }
        }

        return null;
    }

    static int getServerMaximumNegotiableCurveBits(boolean isFips, int[] clientSupportedGroups)
    {
        /*
         * If supported groups wasn't explicitly configured, servers support all available curves.
         */
        int[] serverSupportedGroups = provJdkTlsNamedGroups;

        if (clientSupportedGroups == null)
        {
            if (serverSupportedGroups == null)
            {
                /*
                 * RFC 4492 4. A client that proposes ECC cipher suites may choose not to include these
                 * extensions. In this case, the server is free to choose any one of the elliptic curves
                 * or point formats [...].
                 */
                return isFips
                    ?  FipsUtils.getFipsMaximumCurveBits()
                    :  NamedGroup.getMaximumCurveBits();
            }

            int maxBits = 0;
            for (int i = 0; i < serverSupportedGroups.length; ++i)
            {
                int namedGroup = serverSupportedGroups[i];

                if (!isFips || FipsUtils.isFipsNamedGroup(namedGroup))
                {
                    maxBits = Math.max(maxBits, NamedGroup.getCurveBits(namedGroup));
                }
            }
            return maxBits;
        }
        else
        {
            int maxBits = 0;
            for (int i = 0; i < clientSupportedGroups.length; ++i)
            {
                int namedGroup = clientSupportedGroups[i];

                if (serverSupportedGroups == null || Arrays.contains(serverSupportedGroups, namedGroup))
                {
                    if (!isFips || FipsUtils.isFipsNamedGroup(namedGroup))
                    {
                        maxBits = Math.max(maxBits, NamedGroup.getCurveBits(namedGroup));
                    }
                }
            }
            return maxBits;
        }
    }

    static int getServerMaximumNegotiableFiniteFieldBits(boolean isFips, int[] clientSupportedGroups)
    {
        /*
         * If supported groups wasn't explicitly configured, servers support all available finite fields.
         */
        int[] serverSupportedGroups = provJdkTlsNamedGroups;

        if (clientSupportedGroups == null)
        {
            if (serverSupportedGroups == null)
            {
                return isFips
                    ?  FipsUtils.getFipsMaximumFiniteFieldBits()
                    :  NamedGroup.getMaximumFiniteFieldBits();
            }

            int maxBits = 0;
            for (int i = 0; i < serverSupportedGroups.length; ++i)
            {
                int namedGroup = serverSupportedGroups[i];

                if (!isFips || FipsUtils.isFipsNamedGroup(namedGroup))
                {
                    maxBits = Math.max(maxBits, NamedGroup.getFiniteFieldBits(namedGroup));
                }
            }
            return maxBits;
        }
        else
        {
            int maxBits = 0;
            for (int i = 0; i < clientSupportedGroups.length; ++i)
            {
                int namedGroup = clientSupportedGroups[i];

                if (serverSupportedGroups == null || Arrays.contains(serverSupportedGroups, namedGroup))
                {
                    if (!isFips || FipsUtils.isFipsNamedGroup(namedGroup))
                    {
                        maxBits = Math.max(maxBits, NamedGroup.getFiniteFieldBits(namedGroup));
                    }
                }
            }
            return maxBits;
        }
    }

    static int getServerSelectedCurve(boolean isFips, int minimumCurveBits, int[] clientSupportedGroups)
    {
        /*
         * If supported groups wasn't explicitly configured, servers support all available curves.
         */
        int[] serverSupportedGroups = provJdkTlsNamedGroups;

        for (int i = 0; i < clientSupportedGroups.length; ++i)
        {
            int namedGroup = clientSupportedGroups[i];

            if (serverSupportedGroups == null || Arrays.contains(serverSupportedGroups, namedGroup))
            {
                if (NamedGroup.getCurveBits(namedGroup) >= minimumCurveBits)
                {
                    if (!isFips || FipsUtils.isFipsNamedGroup(namedGroup))
                    {
                        return namedGroup;
                    }
                }
            }
        }

        return -1;
    }

    static int getServerSelectedFiniteField(boolean isFips, int minimumFiniteFieldBits, int[] clientSupportedGroups)
    {
        /*
         * If supported groups wasn't explicitly configured, servers support all available finite fields.
         */
        int[] serverSupportedGroups = provJdkTlsNamedGroups;

        for (int i = 0; i < clientSupportedGroups.length; ++i)
        {
            int namedGroup = clientSupportedGroups[i];

            if (serverSupportedGroups == null || Arrays.contains(serverSupportedGroups, namedGroup))
            {
                if (NamedGroup.getFiniteFieldBits(namedGroup) >= minimumFiniteFieldBits)
                {
                    if (!isFips || FipsUtils.isFipsNamedGroup(namedGroup))
                    {
                        return namedGroup;
                    }
                }
            }
        }

        return -1;
    }
}
