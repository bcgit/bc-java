package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.provider.ProvX509KeyManager.MatchQuality;
import org.bouncycastle.tls.TlsUtils;

class ProvX509KeyManagerSimple
    extends BCX509ExtendedKeyManager
{
    private static final Logger LOG = Logger.getLogger(ProvX509KeyManagerSimple.class.getName());

    private final boolean isInFipsMode;
    private final JcaJceHelper helper;
    private final Map<String, Credential> credentials;

    private static Map<String, Credential> loadCredentials(KeyStore ks, char[] password)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        Map<String, Credential> credentials = new HashMap<String, Credential>(4);

        if (null != ks)
        {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements())
            {
                String alias = aliases.nextElement();
                if (!ks.entryInstanceOf(alias, PrivateKeyEntry.class))
                {
                    continue;
                }

                PrivateKey privateKey = (PrivateKey)ks.getKey(alias, password);
                if (null == privateKey)
                {
                    continue;
                }

                X509Certificate[] certificateChain = JsseUtils.getX509CertificateChain(ks.getCertificateChain(alias));
                if (TlsUtils.isNullOrEmpty(certificateChain))
                {
                    continue;
                }

                credentials.put(alias, new Credential(alias, privateKey, certificateChain));
            }
        }

        return Collections.unmodifiableMap(credentials);
    }

    ProvX509KeyManagerSimple(boolean isInFipsMode, JcaJceHelper helper, KeyStore ks, char[] password)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        this.isInFipsMode = isInFipsMode;
        this.helper = helper;
        this.credentials = loadCredentials(ks, password);
    }

    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        return chooseAlias(ProvX509KeyManager.getKeyTypes(keyTypes), issuers, TransportData.from(socket), false);
    }

    @Override
    public BCX509Key chooseClientKeyBC(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        return chooseKeyBC(ProvX509KeyManager.getKeyTypes(keyTypes), issuers, TransportData.from(socket), false);
    }

    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine)
    {
        return chooseAlias(ProvX509KeyManager.getKeyTypes(keyTypes), issuers, TransportData.from(engine), false);
    }

    @Override
    public BCX509Key chooseEngineClientKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine)
    {
        return chooseKeyBC(ProvX509KeyManager.getKeyTypes(keyTypes), issuers, TransportData.from(engine), false);
    }

    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine)
    {
        return chooseAlias(ProvX509KeyManager.getKeyTypes(keyType), issuers, TransportData.from(engine), true);
    }

    @Override
    public BCX509Key chooseEngineServerKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine)
    {
        return chooseKeyBC(ProvX509KeyManager.getKeyTypes(keyTypes), issuers, TransportData.from(engine), true);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        return chooseAlias(ProvX509KeyManager.getKeyTypes(keyType), issuers, TransportData.from(socket), true);
    }

    @Override
    public BCX509Key chooseServerKeyBC(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        return chooseKeyBC(ProvX509KeyManager.getKeyTypes(keyTypes), issuers, TransportData.from(socket), true);
    }

    public X509Certificate[] getCertificateChain(String alias)
    {
        Credential credential = getCredential(alias);
        return null == credential ? null : credential.certificateChain.clone();
    }

    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        return getAliases(ProvX509KeyManager.getKeyTypes(keyType), issuers, null, false);
    }

    public PrivateKey getPrivateKey(String alias)
    {
        Credential credential = getCredential(alias);
        return null == credential ? null : credential.privateKey;
    }

    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        return getAliases(ProvX509KeyManager.getKeyTypes(keyType), issuers, null, true);
    }

    @Override
    protected BCX509Key getKeyBC(String keyType, String alias)
    {
        Credential credential = getCredential(alias);
        return createKeyBC(keyType, credential);
    }

    private String chooseAlias(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        Match bestMatch = getBestMatch(keyTypes, issuers, transportData, forServer);

        if (bestMatch.compareTo(Match.NOTHING) < 0)
        {
            String keyType = keyTypes.get(bestMatch.keyTypeIndex);
            String alias = getAlias(bestMatch);
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine("Found matching key of type: " + keyType + ", returning alias: " + alias);
            }
            return alias;
        }

        LOG.fine("No matching key found");
        return null;
    }

    private BCX509Key chooseKeyBC(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        Match bestMatch = getBestMatch(keyTypes, issuers, transportData, forServer);

        if (bestMatch.compareTo(Match.NOTHING) < 0)
        {
            String keyType = keyTypes.get(bestMatch.keyTypeIndex);

            BCX509Key keyBC = createKeyBC(keyType, bestMatch.credential);
            if (null != keyBC)
            {
                if (LOG.isLoggable(Level.FINE))
                {
                    LOG.fine("Found matching key of type: " + keyType + ", from alias: " + getAlias(bestMatch));
                }
                return keyBC;
            }
        }

        LOG.fine("No matching key found");
        return null;
    }

    private BCX509Key createKeyBC(String keyType, Credential credential)
    {
        return null == credential
            ?   null
            :   new ProvX509Key(keyType, credential.privateKey, credential.certificateChain);
    }

    private String[] getAliases(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        if (!credentials.isEmpty() && !keyTypes.isEmpty())
        {
            int keyTypeLimit = keyTypes.size(); 
            Set<Principal> uniqueIssuers = ProvX509KeyManager.getUniquePrincipals(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = ProvX509KeyManager.getRequestedHostName(transportData, forServer);
            List<Match> matches = null;

            for (Credential credential : credentials.values())
            {
                Match match = getPotentialMatch(credential, keyTypes, keyTypeLimit, uniqueIssuers, algorithmConstraints,
                    forServer, atDate, requestedHostName);

                if (match.compareTo(Match.NOTHING) < 0)
                {
                    matches = addToMatches(matches, match);
                }
            }

            if (null != matches && !matches.isEmpty())
            {
                // NOTE: We are relying on this being a stable sort
                Collections.sort(matches);

                return getAliases(matches);
            }
        }

        return null;
    }

    private Match getBestMatch(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        Match bestMatchSoFar = Match.NOTHING;

        if (!credentials.isEmpty() && !keyTypes.isEmpty())
        {
            int keyTypeLimit = keyTypes.size(); 
            Set<Principal> uniqueIssuers = ProvX509KeyManager.getUniquePrincipals(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = ProvX509KeyManager.getRequestedHostName(transportData, forServer);

            for (Credential credential : credentials.values())
            {
                Match match = getPotentialMatch(credential, keyTypes, keyTypeLimit, uniqueIssuers,
                    algorithmConstraints, forServer, atDate, requestedHostName);

                if (match.compareTo(bestMatchSoFar) < 0)
                {
                    bestMatchSoFar = match;

                    if (bestMatchSoFar.isIdeal())
                    {
                        return bestMatchSoFar;
                    }
                    if (bestMatchSoFar.isValid())
                    {
                        keyTypeLimit = Math.min(keyTypeLimit, bestMatchSoFar.keyTypeIndex + 1);
                    }
                }
            }
        }

        return bestMatchSoFar;
    }

    private Match getPotentialMatch(Credential credential, List<String> keyTypes, int keyTypeLimit,
        Set<Principal> uniqueIssuers, BCAlgorithmConstraints algorithmConstraints, boolean forServer, Date atDate,
        String requestedHostName)
    {
        X509Certificate[] chain = credential.certificateChain;

        int keyTypeIndex = ProvX509KeyManager.getPotentialKeyType(keyTypes, keyTypeLimit, uniqueIssuers,
            algorithmConstraints, forServer, chain);
        if (keyTypeIndex >= 0)
        {
            MatchQuality quality = ProvX509KeyManager.getKeyTypeQuality(isInFipsMode, helper, keyTypes,
                algorithmConstraints, forServer, atDate, requestedHostName, chain, keyTypeIndex);
            if (MatchQuality.NONE != quality)
            {
                return new Match(quality, keyTypeIndex, credential);
            }
        }
        return Match.NOTHING;
    }

    private Credential getCredential(String alias)
    {
        return null == alias ? null : credentials.get(alias);
    }

    private static List<Match> addToMatches(List<Match> matches, Match match)
    {
        if (null == matches)
        {
            matches = new ArrayList<Match>();
        }

        matches.add(match);
        return matches;
    }

    private static String getAlias(Match match)
    {
        return match.credential.alias;
    }

    private static String[] getAliases(List<Match> matches)
    {
        int count = matches.size(), pos = 0;
        String[] result = new String[count];
        for (Match match : matches)
        {
            result[pos++] = getAlias(match);
        }
        return result;
    }

    private static class Credential
    {
        private final String alias;
        private final PrivateKey privateKey;
        private final X509Certificate[] certificateChain;

        Credential(String alias, PrivateKey privateKey, X509Certificate[] certificateChain)
        {
            this.alias = alias;
            this.privateKey = privateKey;
            this.certificateChain = certificateChain;
        }
    }

    private static final class Match
        implements Comparable<Match>
    {
        static final ProvX509KeyManager.MatchQuality INVALID = ProvX509KeyManager.MatchQuality.MISMATCH_SNI;
        static final Match NOTHING = new Match(ProvX509KeyManager.MatchQuality.NONE, Integer.MAX_VALUE, null);

        final ProvX509KeyManager.MatchQuality quality;
        final int keyTypeIndex;
        final Credential credential;

        Match(ProvX509KeyManager.MatchQuality quality, int keyTypeIndex, Credential credential)
        {
            this.quality = quality;
            this.keyTypeIndex = keyTypeIndex;
            this.credential = credential;
        }

        public int compareTo(Match that)
        {
            boolean thisValid = this.isValid(), thatValid = that.isValid();
            if (thisValid != thatValid)
            {
                return thisValid ? -1 : 1;
            }

            if (this.keyTypeIndex != that.keyTypeIndex)
            {
                return this.keyTypeIndex < that.keyTypeIndex ? -1 : 1;
            }

            return this.quality.compareTo(that.quality);
        }

        boolean isIdeal()
        {
            return ProvX509KeyManager.MatchQuality.OK == quality && 0 == keyTypeIndex;
        }

        boolean isValid()
        {
            return quality.compareTo(INVALID) < 0;
        }
    }
}
