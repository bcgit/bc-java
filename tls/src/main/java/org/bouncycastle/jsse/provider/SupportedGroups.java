package org.bouncycastle.jsse.provider;

import java.util.Vector;
import java.util.logging.Logger;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.NamedGroupRole;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

abstract class SupportedGroups
{
    private static final Logger LOG = Logger.getLogger(SupportedGroups.class.getName());

    private static final String PROPERTY_NAMED_GROUPS = "jdk.tls.namedGroups";

    private static final boolean provDisableChar2 = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.ec.disableChar2", false)
                                                 || PropertyUtils.getBooleanSystemProperty("org.bouncycastle.ec.disable_f2m", false);
    private static final boolean provDisableFFDHE = !PropertyUtils.getBooleanSystemProperty("jsse.enableFFDHE", true);

    private static final int[] provJdkTlsNamedGroups = getJdkTlsNamedGroups(provDisableChar2, provDisableFFDHE);

    private static final int[] clientNamedGroups = getClientNamedGroups(provJdkTlsNamedGroups, provDisableChar2, provDisableFFDHE,
        new int[] {
            NamedGroup.x25519,
            NamedGroup.secp256r1,
            NamedGroup.secp384r1,
            NamedGroup.secp521r1,
            NamedGroup.ffdhe2048,
            NamedGroup.ffdhe3072,
            NamedGroup.ffdhe4096,
        });

    private static int[] getClientNamedGroups(int[] userNamedGroups, boolean disableChar2, boolean disableFFDHE,
        int[] defaultNamedGroups)
    {
        if (null != userNamedGroups)
        {
            return userNamedGroups;
        }

        int[] result = new int[defaultNamedGroups.length];
        int count = 0;
        for (int namedGroup : defaultNamedGroups)
        {
            if (NamedGroup.refersToASpecificGroup(namedGroup)
                && !(disableChar2 && NamedGroup.isChar2Curve(namedGroup))
                && !(disableFFDHE && NamedGroup.refersToASpecificFiniteField(namedGroup)))
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
            LOG.severe("Default named groups contained no usable NamedGroup values");
        }
        return result;
    }

    private static int getDefaultDH(int minimumFiniteFieldBits)
    {
        return minimumFiniteFieldBits <= 2048 ? NamedGroup.ffdhe2048
            :  minimumFiniteFieldBits <= 3072 ? NamedGroup.ffdhe3072
            :  minimumFiniteFieldBits <= 4096 ? NamedGroup.ffdhe4096
            :  minimumFiniteFieldBits <= 6144 ? NamedGroup.ffdhe6144
            :  minimumFiniteFieldBits <= 8192 ? NamedGroup.ffdhe8192
            :  -1;
    }

    // NOTE: Assumed to never return a char-2 curve.
    private static int getDefaultECDH(int minimumCurveBits)
    {
        return minimumCurveBits <= 256 ? NamedGroup.secp256r1
            :  minimumCurveBits <= 384 ? NamedGroup.secp384r1
            :  minimumCurveBits <= 521 ? NamedGroup.secp521r1
            :  -1;
    }

    private static int[] getJdkTlsNamedGroups(boolean disableChar2, boolean disableFFDHE)
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
                LOG.info("'" + PROPERTY_NAMED_GROUPS + "' contains unrecognised NamedGroup: " + name);
            }
            else if (disableChar2 && NamedGroup.isChar2Curve(namedGroup))
            {
                LOG.warning("'" + PROPERTY_NAMED_GROUPS + "' contains disabled characteristic-2 curve: " + name);
            }
            else if (disableFFDHE && NamedGroup.refersToASpecificFiniteField(namedGroup))
            {
                LOG.warning("'" + PROPERTY_NAMED_GROUPS + "' contains disabled finite-field group: " + name);
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

    static Vector<Integer> getClientSupportedGroups(JcaTlsCrypto crypto, boolean isFips,
        Vector<Integer> namedGroupRoles)
    {
        boolean roleDH = namedGroupRoles.contains(NamedGroupRole.dh);
        boolean roleECDH = namedGroupRoles.contains(NamedGroupRole.ecdh);
        boolean roleECDSA = namedGroupRoles.contains(NamedGroupRole.ecdsa);

        Vector<Integer> result = new Vector<Integer>();
        for (int namedGroup : clientNamedGroups)
        {
            if ((roleDH && NamedGroup.refersToASpecificFiniteField(namedGroup))
                || (roleECDH && NamedGroup.refersToAnECDHCurve(namedGroup))
                || (roleECDSA && NamedGroup.refersToAnECDSACurve(namedGroup)))
            {
                if (!isFips || FipsUtils.isFipsNamedGroup(namedGroup))
                {
                    if (crypto.hasNamedGroup(namedGroup))
                    {
                        result.add(namedGroup);
                    }
                }
            }
        }
        return result;
    }

    static int getServerDefaultDH(boolean isFips, int minimumFiniteFieldBits)
    {
        /*
         * If supported groups wasn't explicitly configured, servers support all available finite
         * fields (modulo 'provDisableFFDHE').
         */
        int[] serverSupportedGroups = provJdkTlsNamedGroups;

        if (serverSupportedGroups == null)
        {
            if (provDisableFFDHE)
            {
                return -1;
            }

            if (isFips)
            {
                return FipsUtils.getFipsDefaultDH(minimumFiniteFieldBits);
            }

            return getDefaultDH(minimumFiniteFieldBits);
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
         * (modulo 'provDisableChar2').
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
                if (isFips)
                {
                    return FipsUtils.getFipsMaximumCurveBits();
                }

                if (provDisableChar2)
                {
                    return NamedGroup.getMaximumPrimeCurveBits();
                }

                return NamedGroup.getMaximumCurveBits();
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
                if (provDisableFFDHE)
                {
                    return -1;
                }

                if (isFips)
                {
                    return FipsUtils.getFipsMaximumFiniteFieldBits();
                }

                return NamedGroup.getMaximumFiniteFieldBits();
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

                if (provDisableFFDHE && NamedGroup.refersToASpecificFiniteField(namedGroup))
                {
                    continue;
                }

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

    static int getServerSelectedCurve(JcaTlsCrypto crypto, boolean isFips, int minimumCurveBits,
        int[] clientSupportedGroups)
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

    static int getServerSelectedFiniteField(JcaTlsCrypto crypto, boolean isFips, int minimumFiniteFieldBits,
        int[] clientSupportedGroups)
    {
        if (provDisableFFDHE)
        {
            return -1;
        }

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
