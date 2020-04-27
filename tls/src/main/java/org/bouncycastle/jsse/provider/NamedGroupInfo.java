package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Vector;
import java.util.logging.Logger;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;

class NamedGroupInfo
{
    private static final Logger LOG = Logger.getLogger(NamedGroupInfo.class.getName());

    private static final String PROPERTY_NAMED_GROUPS = "jdk.tls.namedGroups";

    // NOTE: Not all of these are necessarily enabled/supported; it will be checked at runtime
    private static final int[] DEFAULT_CANDIDATES = {
        NamedGroup.x25519,
        NamedGroup.x448,
        NamedGroup.secp256r1,
        NamedGroup.secp384r1,
        NamedGroup.secp521r1,
        NamedGroup.ffdhe2048,
        NamedGroup.ffdhe3072,
        NamedGroup.ffdhe4096,
    };

    static class PerConnection
    {
        // NOTE: Should have predictable iteration order (by preference)
        private final Map<Integer, NamedGroupInfo> local;
        private final boolean localECDSA;

        private List<NamedGroupInfo> peer;

        PerConnection(Map<Integer, NamedGroupInfo> local, boolean localECDSA)
        {
            this.local = local;
            this.localECDSA = localECDSA;

            this.peer = null;
        }

        public synchronized List<NamedGroupInfo> getPeer()
        {
            return peer;
        }

        private synchronized void setPeer(List<NamedGroupInfo> peer)
        {
            this.peer = peer;
        }
    }

    static class PerContext
    {
        private final Map<Integer, NamedGroupInfo> index;
        private final int[] candidates;

        PerContext(Map<Integer, NamedGroupInfo> index, int[] candidates)
        {
            this.index = index;
            this.candidates = candidates;
        }
    }

    static PerConnection createPerConnection(PerContext perContext, ProvSSLParameters sslParameters, ProtocolVersion[] activeProtocolVersions)
    {
        Map<Integer, NamedGroupInfo> local = createLocal(perContext, sslParameters, activeProtocolVersions);
        boolean localECDSA = createLocalECDSA(local);

        return new PerConnection(local, localECDSA);
    }

    static PerContext createPerContext(boolean isFipsContext, JcaTlsCrypto crypto)
    {
        Map<Integer, NamedGroupInfo> index = createIndex(isFipsContext, crypto);
        int[] candidates = createCandidates(index);

        return new PerContext(index, candidates);
    }

    static int getMaximumBitsServerECDH(PerConnection perConnection)
    {
        int maxBits = 0;
        for (NamedGroupInfo namedGroupInfo : getEffectivePeer(perConnection))
        {
            maxBits = Math.max(maxBits, namedGroupInfo.getBitsECDH());
        }
        return maxBits;
    }

    static int getMaximumBitsServerFFDHE(PerConnection perConnection)
    {
        int maxBits = 0;
        for (NamedGroupInfo namedGroupInfo : getEffectivePeer(perConnection))
        {
            maxBits = Math.max(maxBits, namedGroupInfo.getBitsFFDHE());
        }
        return maxBits;
    }

    static NamedGroupInfo getNamedGroup(PerContext perContext, int namedGroup)
    {
        return perContext.index.get(namedGroup);
    }

    static Vector<Integer> getSupportedGroupsLocal(PerConnection perConnection)
    {
        return new Vector<Integer>(perConnection.local.keySet());
    }

    static boolean hasAnyECDSALocal(PerConnection perConnection)
    {
        return perConnection.localECDSA;
    }

    static boolean hasLocal(PerConnection perConnection, int namedGroup)
    {
        return perConnection.local.containsKey(namedGroup);
    }

    static void notifyPeer(PerConnection perConnection, int[] peerNamedGroups)
    {
        List<NamedGroupInfo> peer = createPeer(perConnection, peerNamedGroups);

        perConnection.setPeer(peer);
    }

    static int selectServerECDH(PerConnection perConnection, int minimumBitsECDH)
    {
        for (NamedGroupInfo namedGroupInfo : getEffectivePeer(perConnection))
        {
            if (namedGroupInfo.getBitsECDH() >= minimumBitsECDH)
            {
                return namedGroupInfo.getNamedGroup();
            }
        }
        return -1;
    }

    static int selectServerFFDHE(PerConnection perConnection, int minimumBitsFFDHE)
    {
        for (NamedGroupInfo namedGroupInfo : getEffectivePeer(perConnection))
        {
            if (namedGroupInfo.getBitsFFDHE() >= minimumBitsFFDHE)
            {
                return namedGroupInfo.getNamedGroup();
            }
        }
        return -1;
    }

    private static void addNamedGroup(boolean isFipsContext, JcaTlsCrypto crypto, Map<Integer, NamedGroupInfo> ng,
        int namedGroup, String jcaAlgorithm, boolean supported13, boolean disable)
    {
        if (isFipsContext && !FipsUtils.isFipsNamedGroup(namedGroup))
        {
            // In FIPS mode, non-FIPS groups are currently not even entered into the map
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

    private static int[] createCandidates(Map<Integer, NamedGroupInfo> index)
    {
        String[] names = PropertyUtils.getStringArraySystemProperty(PROPERTY_NAMED_GROUPS);
        if (null == names)
        {
            return DEFAULT_CANDIDATES;
        }

        int[] result = new int[names.length];
        int count = 0;
        for (String name : names)
        {
            int namedGroup = NamedGroup.getByName(Strings.toLowerCase(name));
            if (namedGroup < 0)
            {
                LOG.warning("'" + PROPERTY_NAMED_GROUPS + "' contains unrecognised NamedGroup: " + name);
                continue;
            }

            NamedGroupInfo namedGroupInfo = index.get(namedGroup);
            if (null == namedGroupInfo)
            {
                LOG.warning("'" + PROPERTY_NAMED_GROUPS + "' contains unsupported NamedGroup: " + name);
                continue;
            }

            if (!namedGroupInfo.isEnabled())
            {
                LOG.warning("'" + PROPERTY_NAMED_GROUPS + "' contains disabled NamedGroup: " + name);
                continue;
            }

            result[count++] = namedGroup;
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

    private static Map<Integer, NamedGroupInfo> createIndex(boolean isFipsContext, JcaTlsCrypto crypto)
    {
        Map<Integer, NamedGroupInfo> ng = new TreeMap<Integer, NamedGroupInfo>();

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

        return ng;
    }

    private static Map<Integer, NamedGroupInfo> createLocal(PerContext perContext,
        ProvSSLParameters sslParameters, ProtocolVersion[] activeProtocolVersions)
    {
        ProtocolVersion latest = ProtocolVersion.getLatestTLS(activeProtocolVersions);
        ProtocolVersion earliest = ProtocolVersion.getEarliestTLS(activeProtocolVersions);

        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();
        boolean post13Active = TlsUtils.isTLSv13(latest);
        boolean pre13Active = !TlsUtils.isTLSv13(earliest);

        int count = perContext.candidates.length;
        LinkedHashMap<Integer, NamedGroupInfo> result = new LinkedHashMap<Integer, NamedGroupInfo>(count);
        for (int i = 0; i < count; ++i)
        {
            Integer candidate = Integers.valueOf(perContext.candidates[i]);
            NamedGroupInfo namedGroupInfo = perContext.index.get(candidate);

            if (null != namedGroupInfo
                && !result.containsKey(candidate)
                && namedGroupInfo.isActive(algorithmConstraints, pre13Active, post13Active))
            {
                result.put(candidate, namedGroupInfo);
            }
        }
        return result;
    }

    private static boolean createLocalECDSA(Map<Integer, NamedGroupInfo> local)
    {
        for (NamedGroupInfo namedGroupInfo : local.values())
        {
            if (NamedGroup.refersToAnECDSACurve(namedGroupInfo.getNamedGroup()))
            {
                return true;
            }
        }
        return false;
    }

    private static List<NamedGroupInfo> createPeer(PerConnection perConnection, int[] peerNamedGroups)
    {
        // TODO[jsse] Is there any reason to preserve the unrecognized/disabled groups?

        return getNamedGroupInfos(perConnection.local, peerNamedGroups);
    }

    private static Collection<NamedGroupInfo> getEffectivePeer(PerConnection perConnection)
    {
        List<NamedGroupInfo> peer = perConnection.getPeer();
        if (!peer.isEmpty())
        {
            return peer;
        }

        return perConnection.local.values();
    }

    private static List<NamedGroupInfo> getNamedGroupInfos(Map<Integer, NamedGroupInfo> namedGroupInfos, int[] namedGroups)
    {
        if (null == namedGroups || namedGroups.length < 1)
        {
            return Collections.emptyList();
        }

        int count = namedGroups.length;
        ArrayList<NamedGroupInfo> result = new ArrayList<NamedGroupInfo>(count);
        for (int i = 0; i < count; ++i)
        {
            int namedGroup = namedGroups[i];

            NamedGroupInfo namedGroupInfo = namedGroupInfos.get(namedGroup);
            if (null != namedGroupInfo)
            {
                result.add(namedGroupInfo);
            }
        }
        if (result.isEmpty())
        {
            return Collections.emptyList();
        }
        result.trimToSize();
        return result;
    }

    private final int namedGroup;
    private final String name;
    private final String jcaAlgorithm;
    private final AlgorithmParameters algorithmParameters;
    private final boolean supported13;
    private final boolean enabled;
    private final int bitsECDH; 
    private final int bitsFFDHE; 

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
        this.bitsECDH = NamedGroup.getCurveBits(namedGroup);
        this.bitsFFDHE = NamedGroup.getFiniteFieldBits(namedGroup);
    }

    int getBitsECDH()
    {
        return bitsECDH;
    }

    int getBitsFFDHE()
    {
        return bitsFFDHE;
    }

    String getName()
    {
        return name;
    }

    int getNamedGroup()
    {
        return namedGroup;
    }

    boolean isActive(BCAlgorithmConstraints algorithmConstraints, boolean pre13Active, boolean post13Active)
    {
        return enabled
            && (pre13Active || (post13Active && supported13))
            && isPermittedBy(algorithmConstraints);
    }

    boolean isEnabled()
    {
        return enabled;
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

    private boolean isPermittedBy(BCAlgorithmConstraints algorithmConstraints)
    {
        Set<BCCryptoPrimitive> primitives = JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;

        return algorithmConstraints.permits(primitives, name, null)
            && algorithmConstraints.permits(primitives, jcaAlgorithm, algorithmParameters);
    }
}
