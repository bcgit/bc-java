package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Vector;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Properties;

class NamedGroupInfo
{
    private static final Logger LOG = Logger.getLogger(NamedGroupInfo.class.getName());

    private static final String PROPERTY_NAMED_GROUPS = "jdk.tls.namedGroups";

    // NOTE: Not all of these are necessarily enabled/supported; it will be checked at runtime
    private enum All
    {
        sect163k1(NamedGroup.sect163k1, "EC"),
        sect163r1(NamedGroup.sect163r1, "EC"),
        sect163r2(NamedGroup.sect163r2, "EC"),
        sect193r1(NamedGroup.sect193r1, "EC"),
        sect193r2(NamedGroup.sect193r2, "EC"),
        sect233k1(NamedGroup.sect233k1, "EC"),
        sect233r1(NamedGroup.sect233r1, "EC"),
        sect239k1(NamedGroup.sect239k1, "EC"),
        sect283k1(NamedGroup.sect283k1, "EC"),
        sect283r1(NamedGroup.sect283r1, "EC"),
        sect409k1(NamedGroup.sect409k1, "EC"),
        sect409r1(NamedGroup.sect409r1, "EC"),
        sect571k1(NamedGroup.sect571k1, "EC"),
        sect571r1(NamedGroup.sect571r1, "EC"),
        secp160k1(NamedGroup.secp160k1, "EC"),
        secp160r1(NamedGroup.secp160r1, "EC"),
        secp160r2(NamedGroup.secp160r2, "EC"),
        secp192k1(NamedGroup.secp192k1, "EC"),
        secp192r1(NamedGroup.secp192r1, "EC"),
        secp224k1(NamedGroup.secp224k1, "EC"),
        secp224r1(NamedGroup.secp224r1, "EC"),
        secp256k1(NamedGroup.secp256k1, "EC"),
        secp256r1(NamedGroup.secp256r1, "EC"),
        secp384r1(NamedGroup.secp384r1, "EC"),
        secp521r1(NamedGroup.secp521r1, "EC"),

        brainpoolP256r1(NamedGroup.brainpoolP256r1, "EC"),
        brainpoolP384r1(NamedGroup.brainpoolP384r1, "EC"),
        brainpoolP512r1(NamedGroup.brainpoolP512r1, "EC"),

        x25519(NamedGroup.x25519, "XDH"),
        x448(NamedGroup.x448, "XDH"),

        brainpoolP256r1tls13(NamedGroup.brainpoolP256r1tls13, "EC"),
        brainpoolP384r1tls13(NamedGroup.brainpoolP384r1tls13, "EC"),
        brainpoolP512r1tls13(NamedGroup.brainpoolP512r1tls13, "EC"),

        curveSM2(NamedGroup.curveSM2, "EC"),

        ffdhe2048(NamedGroup.ffdhe2048, "DiffieHellman"),
        ffdhe3072(NamedGroup.ffdhe3072, "DiffieHellman"),
        ffdhe4096(NamedGroup.ffdhe4096, "DiffieHellman"),
        ffdhe6144(NamedGroup.ffdhe6144, "DiffieHellman"),
        ffdhe8192(NamedGroup.ffdhe8192, "DiffieHellman"),

        OQS_mlkem512(NamedGroup.OQS_mlkem512, "ML-KEM"),
        OQS_mlkem768(NamedGroup.OQS_mlkem768, "ML-KEM"),
        OQS_mlkem1024(NamedGroup.OQS_mlkem1024, "ML-KEM"),
        DRAFT_mlkem768(NamedGroup.DRAFT_mlkem768, "ML-KEM"),
        DRAFT_mlkem1024(NamedGroup.DRAFT_mlkem1024, "ML-KEM");

        private final int namedGroup;
        private final String name;
        private final String text;
        private final String jcaAlgorithm;
        private final String jcaGroup;
        private final boolean char2;
        private final boolean supportedPost13;
        private final boolean supportedPre13;
        private final int bitsECDH;
        private final int bitsFFDHE;

        private All(int namedGroup, String jcaAlgorithm)
        {
            this.namedGroup = namedGroup;
            this.name = NamedGroup.getName(namedGroup);
            this.text = NamedGroup.getText(namedGroup);
            this.jcaAlgorithm = jcaAlgorithm;
            this.jcaGroup = NamedGroup.getStandardName(namedGroup);
            this.supportedPost13 = NamedGroup.canBeNegotiated(namedGroup, ProtocolVersion.TLSv13);
            this.supportedPre13 = NamedGroup.canBeNegotiated(namedGroup, ProtocolVersion.TLSv12);
            this.char2 = NamedGroup.isChar2Curve(namedGroup);
            this.bitsECDH = NamedGroup.getCurveBits(namedGroup);
            this.bitsFFDHE = NamedGroup.getFiniteFieldBits(namedGroup);
        }
    }

    private static final int[] CANDIDATES_DEFAULT = {
        NamedGroup.x25519,
        NamedGroup.x448,
        NamedGroup.secp256r1,
        NamedGroup.secp384r1,
        NamedGroup.secp521r1,
        NamedGroup.brainpoolP256r1tls13,
        NamedGroup.brainpoolP384r1tls13,
        NamedGroup.brainpoolP512r1tls13,
        NamedGroup.ffdhe2048,
        NamedGroup.ffdhe3072,
        NamedGroup.ffdhe4096,
    };

    static class PerConnection
    {
        private final LinkedHashMap<Integer, NamedGroupInfo> local;
        private final boolean localECDSA;
        private final AtomicReference<List<NamedGroupInfo>> peer;

        PerConnection(LinkedHashMap<Integer, NamedGroupInfo> local, boolean localECDSA)
        {
            if (local == null)
            {
                throw new NullPointerException("local");
            }

            this.local = local;
            this.localECDSA = localECDSA;
            this.peer = new AtomicReference<List<NamedGroupInfo>>();
        }

        List<NamedGroupInfo> getPeer()
        {
            return peer.get();
        }

        void notifyPeerData(int[] namedGroups)
        {
            // TODO[jsse] Is there any reason to preserve the unrecognized/disabled groups?
            List<NamedGroupInfo> namedGroupInfos = getNamedGroupInfos(local, namedGroups);

            peer.set(namedGroupInfos);
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

    static class DefaultedResult
    {
        private final int result;
        private final boolean defaulted;

        DefaultedResult(int result, boolean defaulted)
        {
            this.result = result;
            this.defaulted = defaulted;
        }

        int getResult()
        {
            return result;
        }

        boolean isDefaulted()
        {
            return defaulted;
        }
    }

    static PerConnection createPerConnectionClient(PerContext perContext, ProvSSLParameters sslParameters,
        ProtocolVersion[] activeProtocolVersions)
    {
        ProtocolVersion latest = ProtocolVersion.getLatestTLS(activeProtocolVersions);
        ProtocolVersion earliest = ProtocolVersion.getEarliestTLS(activeProtocolVersions);

        return createPerConnection(perContext, sslParameters, earliest, latest);
    }

    static PerConnection createPerConnectionServer(PerContext perContext, ProvSSLParameters sslParameters,
        ProtocolVersion negotiatedVersion)
    {
        return createPerConnection(perContext, sslParameters, negotiatedVersion, negotiatedVersion);
    }

    private static PerConnection createPerConnection(PerContext perContext, ProvSSLParameters sslParameters,
        ProtocolVersion earliest, ProtocolVersion latest)
    {
        String[] namedGroups = sslParameters.getNamedGroups();

        int[] candidates;
        if (namedGroups == null)
        {
            candidates = perContext.candidates;
        }
        else
        {
            candidates = createCandidates(perContext.index, namedGroups, "SSLParameters.namedGroups");
        }

        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();
        boolean post13Active = TlsUtils.isTLSv13(latest);
        boolean pre13Active = !TlsUtils.isTLSv13(earliest);

        int count = candidates.length;
        LinkedHashMap<Integer, NamedGroupInfo> local = new LinkedHashMap<Integer, NamedGroupInfo>(count);
        for (int i = 0; i < count; ++i)
        {
            Integer candidate = Integers.valueOf(candidates[i]);
            NamedGroupInfo namedGroupInfo = perContext.index.get(candidate);

            if (null != namedGroupInfo
                && namedGroupInfo.isActive(algorithmConstraints, post13Active, pre13Active))
            {
                // NOTE: Re-insertion doesn't affect iteration order for insertion-order LinkedHashMap
                local.put(candidate, namedGroupInfo);
            }
        }

        boolean localECDSA = hasAnyECDSA(local);

        return new PerConnection(local, localECDSA);
    }

    static PerContext createPerContext(boolean isFipsContext, JcaTlsCrypto crypto)
    {
        Map<Integer, NamedGroupInfo> index = createIndex(isFipsContext, crypto);
        int[] candidates = createCandidatesFromProperty(index, PROPERTY_NAMED_GROUPS);

        return new PerContext(index, candidates);
    }

    static DefaultedResult getMaximumBitsServerECDH(PerConnection perConnection)
    {
        int maxBits = 0;
        List<NamedGroupInfo> peer = perConnection.getPeer();
        if (peer != null)
        {
            for (NamedGroupInfo namedGroupInfo : peer)
            {
                int bits = namedGroupInfo.getBitsECDH();
                if (bits > maxBits)
                {
                    if (perConnection.local.containsKey(namedGroupInfo.getNamedGroup()))
                    {
                        maxBits = bits;
                    }
                }
            }
        }
        else
        {
            /*
             * RFC 4492 4. A client that proposes ECC cipher suites may choose not to include these
             * extensions. In this case, the server is free to choose any one of the elliptic curves or point
             * formats [...].
             */
            for (NamedGroupInfo namedGroupInfo : perConnection.local.values())
            {
                maxBits = Math.max(maxBits, namedGroupInfo.getBitsECDH());
            }
        }
        return new DefaultedResult(maxBits, peer == null);
    }

    static DefaultedResult getMaximumBitsServerFFDHE(PerConnection perConnection)
    {
        int maxBits = 0;
        boolean anyPeerFF = false;
        List<NamedGroupInfo> peer = perConnection.getPeer();
        if (peer != null)
        {
            for (NamedGroupInfo namedGroupInfo : peer)
            {
                int namedGroup = namedGroupInfo.getNamedGroup();
                anyPeerFF |= NamedGroup.isFiniteField(namedGroup);

                int bits = namedGroupInfo.getBitsFFDHE();
                if (bits > maxBits)
                {
                    if (perConnection.local.containsKey(namedGroup))
                    {
                        maxBits = bits;
                    }
                }
            }
        }
        if (!anyPeerFF)
        {
            /*
             * RFC 7919 4. If [...] the Supported Groups extension is either absent from the ClientHello
             * entirely or contains no FFDHE groups (i.e., no codepoints between 256 and 511, inclusive), then
             * the server [...] MAY select an FFDHE cipher suite and offer an FFDHE group of its choice [...].
             */
            for (NamedGroupInfo namedGroupInfo : perConnection.local.values())
            {
                maxBits = Math.max(maxBits, namedGroupInfo.getBitsFFDHE());
            }
        }
        return new DefaultedResult(maxBits, !anyPeerFF);
    }

    static NamedGroupInfo getNamedGroup(PerContext perContext, int namedGroup)
    {
        return perContext.index.get(namedGroup);
    }

    static Vector<Integer> getSupportedGroupsLocalClient(PerConnection perConnection)
    {
        return new Vector<Integer>(perConnection.local.keySet());
    }

    static int[] getSupportedGroupsLocalServer(PerConnection perConnection)
    {
        Set<Integer> keys = perConnection.local.keySet();
        int count = keys.size(), pos = 0;
        int[] result = new int[count];
        for (Integer key : keys)
        {
            result[pos++] = key.intValue();
        }
        return result;
    }

    static boolean hasAnyECDSALocal(PerConnection perConnection)
    {
        return perConnection.localECDSA;
    }

    static boolean hasLocal(PerConnection perConnection, int namedGroup)
    {
        return perConnection.local.containsKey(namedGroup);
    }

    static DefaultedResult selectServerECDH(PerConnection perConnection, int minimumBitsECDH)
    {
        List<NamedGroupInfo> peer = perConnection.getPeer();
        if (peer != null)
        {
            for (NamedGroupInfo namedGroupInfo : peer)
            {
                if (namedGroupInfo.getBitsECDH() >= minimumBitsECDH)
                {
                    int namedGroup = namedGroupInfo.getNamedGroup();
                    if (perConnection.local.containsKey(namedGroup))
                    {
                        return new DefaultedResult(namedGroup, false);
                    }
                }
            }
        }
        else
        {
            /*
             * RFC 4492 4. A client that proposes ECC cipher suites may choose not to include these
             * extensions. In this case, the server is free to choose any one of the elliptic curves or point
             * formats [...].
             */
            for (NamedGroupInfo namedGroupInfo : perConnection.local.values())
            {
                if (namedGroupInfo.getBitsECDH() >= minimumBitsECDH)
                {
                    return new DefaultedResult(namedGroupInfo.getNamedGroup(), true);
                }
            }
        }
        return new DefaultedResult(-1, peer == null);
    }

    static DefaultedResult selectServerFFDHE(PerConnection perConnection, int minimumBitsFFDHE)
    {
        boolean anyPeerFF = false;
        List<NamedGroupInfo> peer = perConnection.getPeer();
        if (peer != null)
        {
            for (NamedGroupInfo namedGroupInfo : peer)
            {
                int namedGroup = namedGroupInfo.getNamedGroup();
                anyPeerFF |= NamedGroup.isFiniteField(namedGroup);

                if (namedGroupInfo.getBitsFFDHE() >= minimumBitsFFDHE)
                {
                    if (perConnection.local.containsKey(namedGroup))
                    {
                        return new DefaultedResult(namedGroup, false);
                    }
                }
            }
        }
        if (!anyPeerFF)
        {
            /*
             * RFC 7919 4. If [...] the Supported Groups extension is either absent from the ClientHello
             * entirely or contains no FFDHE groups (i.e., no codepoints between 256 and 511, inclusive), then
             * the server [...] MAY select an FFDHE cipher suite and offer an FFDHE group of its choice [...].
             */
            for (NamedGroupInfo namedGroupInfo : perConnection.local.values())
            {
                if (namedGroupInfo.getBitsFFDHE() >= minimumBitsFFDHE)
                {
                    return new DefaultedResult(namedGroupInfo.getNamedGroup(), true);
                }
            }
        }
        return new DefaultedResult(-1, !anyPeerFF);
    }

    private static void addNamedGroup(boolean isFipsContext, JcaTlsCrypto crypto, boolean disableChar2,
        boolean disableFFDHE, Map<Integer, NamedGroupInfo> ng, All all)
    {
        final int namedGroup = all.namedGroup;

        if (isFipsContext && !FipsUtils.isFipsNamedGroup(namedGroup))
        {
            // In FIPS mode, non-FIPS groups are currently not even entered into the map
            return;
        }

        boolean disable = (disableChar2 && all.char2) || (disableFFDHE && all.bitsFFDHE > 0);

        boolean enabled = !disable && (null != all.jcaGroup) && crypto.hasNamedGroup(namedGroup);

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

        NamedGroupInfo namedGroupInfo = new NamedGroupInfo(all, algorithmParameters, enabled);

        if (null != ng.put(namedGroup, namedGroupInfo))
        {
            throw new IllegalStateException("Duplicate entries for NamedGroupInfo");
        }
    }

    private static int[] createCandidatesFromProperty(Map<Integer, NamedGroupInfo> index, String propertyName)
    {
        String[] names = PropertyUtils.getStringArraySystemProperty(propertyName);
        if (null == names)
        {
            return CANDIDATES_DEFAULT;
        }

        return createCandidates(index, names, propertyName);
    }

    private static int[] createCandidates(Map<Integer, NamedGroupInfo> index, String[] names, String description)
    {
        int[] result = new int[names.length];
        int count = 0;
        for (String name : names)
        {
            int namedGroup = getNamedGroupByName(name);
            if (namedGroup < 0)
            {
                LOG.warning("'" + description + "' contains unrecognised NamedGroup: " + name);
                continue;
            }

            NamedGroupInfo namedGroupInfo = index.get(namedGroup);
            if (null == namedGroupInfo)
            {
                LOG.warning("'" + description + "' contains unsupported NamedGroup: " + name);
                continue;
            }

            if (!namedGroupInfo.isEnabled())
            {
                LOG.warning("'" + description + "' contains disabled NamedGroup: " + name);
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
            LOG.severe("'" + description + "' contained no usable NamedGroup values");
        }
        return result;
    }

    private static Map<Integer, NamedGroupInfo> createIndex(boolean isFipsContext, JcaTlsCrypto crypto)
    {
        Map<Integer, NamedGroupInfo> ng = new TreeMap<Integer, NamedGroupInfo>();

        final boolean disableChar2 =
            PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.ec.disableChar2", false) ||
            Properties.isOverrideSet("org.bouncycastle.ec.disable_f2m");

        final boolean disableFFDHE = !PropertyUtils.getBooleanSystemProperty("jsse.enableFFDHE", true);

        for (All all : All.values())
        {
            addNamedGroup(isFipsContext, crypto, disableChar2, disableFFDHE, ng, all);
        }

        return ng;
    }

    private static int getNamedGroupByName(String name)
    {
        for (All all : All.values())
        {
            if (all.name.equalsIgnoreCase(name))
            {
                return all.namedGroup;
            }
        }

        return -1;
    }

    private static List<NamedGroupInfo> getNamedGroupInfos(Map<Integer, NamedGroupInfo> namedGroupInfos,
        int[] namedGroups)
    {
        if (namedGroups == null)
        {
            return null;
        }
        if (namedGroups.length < 1)
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

    private static boolean hasAnyECDSA(Map<Integer, NamedGroupInfo> local)
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

    private final All all;
    private final AlgorithmParameters algorithmParameters;
    private final boolean enabled;

    NamedGroupInfo(All all, AlgorithmParameters algorithmParameters, boolean enabled)
    {
        this.all = all;
        this.algorithmParameters = algorithmParameters;
        this.enabled = enabled;
    }

    int getBitsECDH()
    {
        return all.bitsECDH;
    }

    int getBitsFFDHE()
    {
        return all.bitsFFDHE;
    }

    String getJcaAlgorithm()
    {
        return all.jcaAlgorithm;
    }

    String getJcaGroup()
    {
        return all.jcaGroup;
    }

    int getNamedGroup()
    {
        return all.namedGroup;
    }

    boolean isActive(BCAlgorithmConstraints algorithmConstraints, boolean post13Active, boolean pre13Active)
    {
        return enabled
            && ((post13Active && isSupportedPost13()) || (pre13Active && isSupportedPre13()))
            && isPermittedBy(algorithmConstraints);
    }

    boolean isEnabled()
    {
        return enabled;
    }

    boolean isSupportedPost13()
    {
        return all.supportedPost13;
    }

    boolean isSupportedPre13()
    {
        return all.supportedPre13;
    }

    @Override
    public String toString()
    {
        return all.text;
    }

    private boolean isPermittedBy(BCAlgorithmConstraints algorithmConstraints)
    {
        Set<BCCryptoPrimitive> primitives = JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;

        return algorithmConstraints.permits(primitives, getJcaGroup(), null)
            && algorithmConstraints.permits(primitives, getJcaAlgorithm(), algorithmParameters);
    }
}
