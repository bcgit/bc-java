package org.bouncycastle.jsse.provider;

import java.util.Vector;
import java.util.logging.Logger;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.NamedGroupRole;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

abstract class SupportedGroups
{
    private static final Logger LOG = Logger.getLogger(SupportedGroups.class.getName());

    private static final String PROPERTY_NAMED_GROUPS = "jdk.tls.namedGroups";

    private static final boolean provDisableChar2 = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.ec.disableChar2", false)
        || PropertyUtils.getBooleanSystemProperty("org.bouncycastle.ec.disable_f2m", false);
    private static final int[] provJdkTlsNamedGroups = getJdkTlsNamedGroups(provDisableChar2);

    /*
     * IMPORTANT: This list is currently assumed by the code to not contain any char-2 curves.
     */
    private static final int[] defaultClientNamedGroups = new int[]{
        NamedGroup.x25519,
        NamedGroup.secp256r1,
        NamedGroup.secp384r1,
        NamedGroup.secp521r1,
        NamedGroup.ffdhe2048,
        NamedGroup.ffdhe3072,
        NamedGroup.ffdhe4096,
    };

    private static int getDefaultDH(int minimumFiniteFieldBits)
    {
        return minimumFiniteFieldBits <= 2048 ? NamedGroup.ffdhe2048
            :  minimumFiniteFieldBits <= 3072 ? NamedGroup.ffdhe3072
            :  minimumFiniteFieldBits <= 4096 ? NamedGroup.ffdhe4096
            :  minimumFiniteFieldBits <= 6144 ? NamedGroup.ffdhe6144
            :  minimumFiniteFieldBits <= 8192 ? NamedGroup.ffdhe8192
            :  -1;
    }

    private static int getDefaultECDH(int minimumCurveBits)
    {
        return minimumCurveBits <= 256 ? NamedGroup.secp256r1
            :  minimumCurveBits <= 384 ? NamedGroup.secp384r1
            :  minimumCurveBits <= 521 ? NamedGroup.secp521r1
            :  -1;
    }

    private static int[] getJdkTlsNamedGroups(boolean provDisableChar2)
    {
        String[] names = PropertyUtils.getStringArraySystemProperty(PROPERTY_NAMED_GROUPS);
        if (null == names)
        {
            return null;
        }

        int[] result = new int[names.length];
        int count = 0;
        for (String name : names)
        {
            int namedGroup = NamedGroup.getByName(Strings.toLowerCase(name));
            if (namedGroup < 0)
            {
                LOG.warning("'" + PROPERTY_NAMED_GROUPS + "' contains unrecognised NamedGroup: " + name);
            }
            else if (provDisableChar2 && NamedGroup.isChar2Curve(namedGroup))
            {
                LOG.warning("'" + PROPERTY_NAMED_GROUPS + "' contains disabled characteristic-2 curve: " + name);
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
            LOG.severe("'" + PROPERTY_NAMED_GROUPS + "' contained no usable NamedGroup values");
        }
        return result;
    }

    static Vector getClientSupportedGroups(TlsCrypto crypto, boolean isFips, Vector namedGroupRoles)
    {
        int[] namedGroups = provJdkTlsNamedGroups != null ? provJdkTlsNamedGroups : defaultClientNamedGroups;

        boolean roleDH = namedGroupRoles.contains(NamedGroupRole.dh);
        boolean roleECDH = namedGroupRoles.contains(NamedGroupRole.ecdh);
        boolean roleECDSA = namedGroupRoles.contains(NamedGroupRole.ecdsa);

        Vector result = new Vector();
        for (int namedGroup : namedGroups)
        {
            if ((roleDH && NamedGroup.refersToASpecificFiniteField(namedGroup))
                || (roleECDH && NamedGroup.refersToASpecificCurve(namedGroup))
                || (roleECDSA && NamedGroup.refersToAnECDSACurve(namedGroup)))
            {
                if (!isFips || FipsUtils.isFipsNamedGroup(namedGroup))
                {
                    if (crypto.hasNamedGroup(namedGroup))
                    {
                        result.addElement(namedGroup);
                    }
                }
            }
        }
        return result;
    }

    static int getServerDefaultDH(boolean isFips, int minimumFiniteFieldBits)
    {
        /*
         * If supported groups wasn't explicitly configured, servers support all available finite fields.
         */
        int[] serverSupportedGroups = provJdkTlsNamedGroups;

        if (serverSupportedGroups == null)
        {
            return isFips
                ?   FipsUtils.getFipsDefaultDH(minimumFiniteFieldBits)
                :   getDefaultDH(minimumFiniteFieldBits);
        }

        for (int namedGroup : serverSupportedGroups)
        {
            if (NamedGroup.getFiniteFieldBits(namedGroup) >= minimumFiniteFieldBits)
            {
                if (!isFips || FipsUtils.isFipsNamedGroup(namedGroup))
                {
                    return namedGroup;
                }
            }
        }

        return -1;
    }

    static int getServerDefaultECDH(boolean isFips, int minimumCurveBits)
    {
        /*
         * If supported groups wasn't explicitly configured, servers support all available curves
         * (modulo 'provDisableF2m').
         */
        int[] serverSupportedGroups = provJdkTlsNamedGroups;

        if (serverSupportedGroups == null)
        {
            if (isFips)
            {
                return FipsUtils.getFipsDefaultECDH(minimumCurveBits);
            }

            return getDefaultECDH(minimumCurveBits);
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

    static int getServerMaximumNegotiableCurveBits(boolean isFips, int[] clientSupportedGroups)
    {
        /*
         * If supported groups wasn't explicitly configured, servers support all available curves
         * (modulo 'provDisableF2m').
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
                return isFips           ?   FipsUtils.getFipsMaximumCurveBits()
                    :  provDisableChar2 ?   NamedGroup.getMaximumPrimeCurveBits()
                    :                       NamedGroup.getMaximumCurveBits();
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

                if (provDisableChar2 && NamedGroup.isChar2Curve(namedGroup))
                {
                    continue;
                }

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

    static int getServerSelectedCurve(TlsCrypto crypto, boolean isFips, int minimumCurveBits, int[] clientSupportedGroups)
    {
        /*
         * If supported groups wasn't explicitly configured, servers support all available curves
         * (modulo 'provDisableF2m').
         */
        int[] serverSupportedGroups = provJdkTlsNamedGroups;

        for (int i = 0; i < clientSupportedGroups.length; ++i)
        {
            int namedGroup = clientSupportedGroups[i];

            if (provDisableChar2 && NamedGroup.isChar2Curve(namedGroup))
            {
                continue;
            }

            if (serverSupportedGroups == null || Arrays.contains(serverSupportedGroups, namedGroup))
            {
                if (NamedGroup.getCurveBits(namedGroup) >= minimumCurveBits)
                {
                    if (!isFips || FipsUtils.isFipsNamedGroup(namedGroup))
                    {
                        if (crypto.hasNamedGroup(namedGroup))
                        {
                            return namedGroup;
                        }
                    }
                }
            }
        }

        return -1;
    }

    static int getServerSelectedFiniteField(TlsCrypto crypto, boolean isFips, int minimumFiniteFieldBits, int[] clientSupportedGroups)
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
                        if (crypto.hasNamedGroup(namedGroup))
                        {
                            return namedGroup;
                        }
                    }
                }
            }
        }

        return -1;
    }
}
