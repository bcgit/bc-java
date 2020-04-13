package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

class NamedGroupInfo
{
    // TODO Support jdk.tls.namedGroups
    // NOTE: Not all of these are necessarily enabled/supported; it will be checked at runtime
    private static final int[] DEFAULT_ACTIVE = {
        NamedGroup.x25519,
        NamedGroup.x448,
        NamedGroup.secp256r1,
        NamedGroup.secp384r1,
        NamedGroup.secp521r1,
        NamedGroup.ffdhe2048,
        NamedGroup.ffdhe3072,
        NamedGroup.ffdhe4096,
    };

    static Map<Integer, NamedGroupInfo> createNamedGroupMap(ProvSSLContextSpi context, JcaTlsCrypto crypto)
    {
        Map<Integer, NamedGroupInfo> ng = new TreeMap<Integer, NamedGroupInfo>();

        final boolean isFipsContext = context.isFips();

        final boolean disableChar2 = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.ec.disableChar2", false)
                                  || PropertyUtils.getBooleanSystemProperty("org.bouncycastle.ec.disable_f2m", false);

        final boolean disableFFDHE = !PropertyUtils.getBooleanSystemProperty("jsse.enableFFDHE", true);

        addNamedGroups(isFipsContext, crypto, ng, "EC", false, disableChar2,
            NamedGroup.sect163k1,
            NamedGroup.sect163r1,
            NamedGroup.sect163r2,
            NamedGroup.sect193r1,
            NamedGroup.sect193r2,
            NamedGroup.sect233k1,
            NamedGroup.sect233r1,
            NamedGroup.sect239k1,
            NamedGroup.sect283k1,
            NamedGroup.sect283r1,
            NamedGroup.sect409k1,
            NamedGroup.sect409r1,
            NamedGroup.sect571k1,
            NamedGroup.sect571r1);

        addNamedGroups(isFipsContext, crypto, ng, "EC", false, false,
            NamedGroup.secp160k1,
            NamedGroup.secp160r1,
            NamedGroup.secp160r2,
            NamedGroup.secp192k1,
            NamedGroup.secp192r1,
            NamedGroup.secp224k1,
            NamedGroup.secp224r1,
            NamedGroup.secp256k1);

        addNamedGroups(isFipsContext, crypto, ng, "EC", true, false,
            NamedGroup.secp256r1,
            NamedGroup.secp384r1,
            NamedGroup.secp521r1);

        // TODO[tls13] Probably someone is going to want these enabled in TLSv13, despite RFC 8446
        addNamedGroups(isFipsContext, crypto, ng, "EC", false, false,
            NamedGroup.brainpoolP256r1,
            NamedGroup.brainpoolP384r1,
            NamedGroup.brainpoolP512r1);

        addNamedGroups(isFipsContext, crypto, ng, "XDH", true, false,
            NamedGroup.x25519,
            NamedGroup.x448);

        addNamedGroups(isFipsContext, crypto, ng, "DiffieHellman", true, disableFFDHE,
            NamedGroup.ffdhe2048,
            NamedGroup.ffdhe3072,
            NamedGroup.ffdhe4096,
            NamedGroup.ffdhe6144,
            NamedGroup.ffdhe8192);

        return Collections.unmodifiableMap(ng);
    }

    static List<NamedGroupInfo> getActiveNamedGroups(Map<Integer, NamedGroupInfo> namedGroupMap,
        ProvSSLParameters sslParameters, ProtocolVersion[] activeProtocolVersions)
    {
        // TODO[tls13] NamedGroupInfo instances need to know their valid versions

        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();

        int count = DEFAULT_ACTIVE.length;
        ArrayList<NamedGroupInfo> result = new ArrayList<NamedGroupInfo>(count);
        for (int i = 0; i < count; ++i)
        {
            NamedGroupInfo namedGroupInfo = namedGroupMap.get(DEFAULT_ACTIVE[i]);
            if (null != namedGroupInfo
                && namedGroupInfo.isActive(algorithmConstraints))
            {
                result.add(namedGroupInfo);
            }
        }
        if (result.isEmpty())
        {
            return null;
        }
        result.trimToSize();
        return Collections.unmodifiableList(result);
    }

    static List<NamedGroupInfo> getNamedGroups(Map<Integer, NamedGroupInfo> namedGroupMap, int[] namedGroups)
    {
        if (null == namedGroups || namedGroups.length < 1)
        {
            return null;
        }

        int count = namedGroups.length;
        ArrayList<NamedGroupInfo> result = new ArrayList<NamedGroupInfo>(count);
        for (int i = 0; i < count; ++i)
        {
            int namedGroup = namedGroups[i];

            NamedGroupInfo namedGroupInfo = namedGroupMap.get(namedGroup);
            if (null != namedGroupInfo)
            {
                result.add(namedGroupInfo);
            }
        }
        if (result.isEmpty())
        {
            return null;
        }
        result.trimToSize();
        return Collections.unmodifiableList(result);
    }

    private static void addNamedGroup(boolean isFipsContext, JcaTlsCrypto crypto, Map<Integer, NamedGroupInfo> ng,
        int namedGroup, String jcaAlgorithm, boolean supported13, boolean disable)
    {
        if (isFipsContext && !FipsUtils.isFipsNamedGroup(namedGroup))
        {
            // Non-FIPS groups are currently not even entered into the map
            return;
        }

        boolean enabled = !disable && crypto.hasNamedGroup(namedGroup);

        AlgorithmParameters algorithmParameters = null;
        if (enabled)
        {
            // TODO[jsse] Consider also fetching 'jcaAlgorithm'
            try
            {
                algorithmParameters = crypto.getNamedGroupAlgorithmParameters(namedGroup);
            }
            catch (Exception e)
            {
                enabled = false;
            }
        }

        NamedGroupInfo namedGroupInfo = new NamedGroupInfo(namedGroup, jcaAlgorithm, algorithmParameters, supported13,
            enabled);

        if (null != ng.put(namedGroup, namedGroupInfo))
        {
            throw new IllegalStateException("Duplicate entries for NamedGroupInfo");
        }
    }

    private static void addNamedGroups(boolean isFipsContext, JcaTlsCrypto crypto, Map<Integer, NamedGroupInfo> ng,
        String jcaAlgorithm, boolean supported13, boolean disable, int... namedGroups)
    {
        for (int namedGroup : namedGroups)
        {
            addNamedGroup(isFipsContext, crypto, ng, namedGroup, jcaAlgorithm, supported13, disable);
        }
    }

    private final int namedGroup;
    private final String name;
    private final String jcaAlgorithm;
    private final AlgorithmParameters algorithmParameters;
    private final boolean supported13;
    private final boolean enabled;

    NamedGroupInfo(int namedGroup, String jcaAlgorithm, AlgorithmParameters algorithmParameters, boolean supported13,
        boolean enabled)
    {
        if (!TlsUtils.isValidUint16(namedGroup))
        {
            throw new IllegalArgumentException();
        }

        this.namedGroup = namedGroup;
        this.name = NamedGroup.getName(namedGroup);
        this.jcaAlgorithm = jcaAlgorithm;
        this.algorithmParameters = algorithmParameters;
        this.supported13 = supported13;
        this.enabled = enabled;
    }

    String getName()
    {
        return name;
    }

    int getNamedGroup()
    {
        return namedGroup;
    }

    boolean isActive(BCAlgorithmConstraints algorithmConstraints)
    {
        /*
         * TODO[tls13] Exclude based on per-instance valid protocol version ranges. Presumably
         * callers of this method want to exclude historical groups from TLS 1.3.
         */
        return enabled
            && isPermittedBy(algorithmConstraints);
    }

    boolean isEnabled()
    {
        return enabled;
    }

    boolean isPermittedBy(BCAlgorithmConstraints algorithmConstraints)
    {
        Set<BCCryptoPrimitive> primitives = JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;

        return algorithmConstraints.permits(primitives, name, null)
            && algorithmConstraints.permits(primitives, jcaAlgorithm, algorithmParameters);
    }

    boolean isSupported13()
    {
        return supported13;
    }

    @Override
    public String toString()
    {
        return NamedGroup.getText(namedGroup);
    }
}
