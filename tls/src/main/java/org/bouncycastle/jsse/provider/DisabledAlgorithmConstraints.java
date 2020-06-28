package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;

class DisabledAlgorithmConstraints
    extends AbstractAlgorithmConstraints
{
    private static final Logger LOG = Logger.getLogger(DisabledAlgorithmConstraints.class.getName());

    private static final String INCLUDE_PREFIX = "include ";
    private static final String KEYWORD_KEYSIZE = "keySize";

    static DisabledAlgorithmConstraints create(AlgorithmDecomposer decomposer, String propertyName, String defaultValue)
    {
        String[] entries = PropertyUtils.getStringArraySecurityProperty(propertyName, defaultValue);
        if (null == entries)
        {
            return null;
        }

        Set<String> disabledAlgorithms = new HashSet<String>();
        Map<String, List<Constraint>> constraintsMap = new HashMap<String, List<Constraint>>();

        for (int i = 0; i < entries.length; ++i)
        {
            if (!addConstraint(disabledAlgorithms, constraintsMap, entries[i]))
            {
                // TODO[jsse] Support a property to make this a strict failure?
                LOG.warning("Ignoring unsupported entry in '" + propertyName + "': " + entries[i]);
            }
        }

        return new DisabledAlgorithmConstraints(decomposer, Collections.unmodifiableSet(disabledAlgorithms),
            Collections.unmodifiableMap(constraintsMap));
    }

    private static boolean addConstraint(Set<String> disabledAlgorithms, Map<String, List<Constraint>> constraintsMap,
        String entry)
    {
        // TODO[jsse] SunJSSE now supports e.g. "include jdk.disabled.namedCurves"
        if (entry.regionMatches(true, 0, INCLUDE_PREFIX, 0, INCLUDE_PREFIX.length()))
        {
            return false;
        }

        // TODO[jsse] Caution if adding namedCurves support: some curves names could contain spaces
        // TODO[jsse] Support any whitespace rather than just ' '?

        int spacePos = entry.indexOf(' ');
        if (spacePos < 0)
        {
            String algorithm = getCanonicalAlgorithm(entry);
            disabledAlgorithms.add(algorithm);
            addConstraint(constraintsMap, algorithm, DisabledConstraint.INSTANCE);
            return true;
        }

        String algorithm = getCanonicalAlgorithm(entry.substring(0, spacePos));
        String policy = entry.substring(spacePos + 1).trim();

        int ampPos = policy.indexOf('&');
        if (ampPos >= 0)
        {
            // TODO Support multi-constraint policies (and other types)
            return false;
        }

        if (policy.startsWith(KEYWORD_KEYSIZE))
        {
            StringTokenizer tokenizer = new StringTokenizer(policy);
            if (!KEYWORD_KEYSIZE.equals(tokenizer.nextToken()))
            {
                return false;
            }

            BinOp op = BinOp.parse(tokenizer.nextToken());
            int constraint = Integer.parseInt(tokenizer.nextToken());

            if (tokenizer.hasMoreTokens())
            {
                return false;
            }

            addConstraint(constraintsMap, algorithm, new KeySizeConstraint(op, constraint));
            return true;
        }

        return false;
    }

    private static void addConstraint(Map<String, List<Constraint>> constraintsMap, String algorithm,
        Constraint constraint)
    {
        List<Constraint> constraintList = constraintsMap.get(algorithm);
        if (null == constraintList)
        {
            constraintList = new ArrayList<Constraint>(1);
            constraintsMap.put(algorithm, constraintList);
        }

        constraintList.add(constraint);
    }

    private static String getCanonicalAlgorithm(String algorithm)
    {
        if ("DiffieHellman".equalsIgnoreCase(algorithm))
        {
            return "DH";
        }

        return algorithm.toUpperCase(Locale.ENGLISH).replace("SHA-", "SHA");
    }

    private static String getConstraintsAlgorithm(String algorithm, AlgorithmParameters parameters)
    {
        if (null != parameters)
        {
            String parametersAlgorithm = parameters.getAlgorithm();
            if (null != parametersAlgorithm)
            {
                String canonicalAlgorithm = getCanonicalAlgorithm(algorithm);
                if (canonicalAlgorithm.equalsIgnoreCase(getCanonicalAlgorithm(parametersAlgorithm)))
                {
                    return canonicalAlgorithm;
                }
            }
        }
        return null;
    }

    private static String getConstraintsAlgorithm(Key key)
    {
        if (null != key)
        {
            String keyAlgorithm = JsseUtils.getKeyAlgorithm(key);
            if (null != keyAlgorithm)
            {
                return getCanonicalAlgorithm(keyAlgorithm);
            }
        }
        return null;
    }

    private final Set<String> disabledAlgorithms;
    private final Map<String, List<Constraint>> constraintsMap;

    private DisabledAlgorithmConstraints(AlgorithmDecomposer decomposer, Set<String> disabledAlgorithms,
        Map<String, List<Constraint>> constraintsMap)
    {
        super(decomposer);

        this.disabledAlgorithms = disabledAlgorithms;
        this.constraintsMap = constraintsMap;
    }

    public final boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters)
    {
        checkPrimitives(primitives);
        checkAlgorithmName(algorithm);

        if (containsAnyPartIgnoreCase(disabledAlgorithms, algorithm))
        {
            return false;
        }

        for (Constraint constraint : getConstraints(getConstraintsAlgorithm(algorithm, parameters)))
        {
            if (!constraint.permits(parameters))
            {
                return false;
            }
        }

        return true;
    }

    public final boolean permits(Set<BCCryptoPrimitive> primitives, Key key)
    {
        return checkConstraints(primitives, null, key, null);
    }

    public final boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, Key key,
        AlgorithmParameters parameters)
    {
        checkAlgorithmName(algorithm);

        return checkConstraints(primitives, algorithm, key, parameters);
    }

    private boolean checkConstraints(Set<BCCryptoPrimitive> primitives, String algorithm, Key key,
        AlgorithmParameters parameters)
    {
        checkPrimitives(primitives);
        checkKey(key);

        if (JsseUtils.isNameSpecified(algorithm)
            && !permits(primitives, algorithm, parameters))
        {
            return false;
        }

        if (!permits(primitives, JsseUtils.getKeyAlgorithm(key), null))
        {
            return false;
        }

        // TODO[jsse] SunJSSE also checks the named curve for EC keys

        for (Constraint constraint : getConstraints(getConstraintsAlgorithm(key)))
        {
            if (!constraint.permits(key))
            {
                return false;
            }
        }

        return true;
    }

    private List<Constraint> getConstraints(String algorithm)
    {
        if (null != algorithm)
        {
            List<Constraint> result = constraintsMap.get(algorithm);
            if (null != result)
            {
                return result;
            }
        }
        return Collections.<Constraint> emptyList();
    }

    private static enum BinOp
    {
        EQ("=="), GE(">="), GT(">"), LE("<="), LT("<"), NE("!=");

        static boolean eval(BinOp op, int lhs, int rhs)
        {
            switch (op)
            {
            case EQ:    return lhs == rhs;
            case GE:    return lhs >= rhs;
            case GT:    return lhs >  rhs;
            case LE:    return lhs <= rhs;
            case LT:    return lhs <  rhs;
            case NE:    return lhs != rhs;
            default:    return true;
            }
        }

        static BinOp parse(String s)
        {
            for (BinOp op : BinOp.values())
            {
                if (op.s.equals(s))
                {
                    return op;
                }
            }
            throw new IllegalArgumentException("'s' is not a valid operator: " + s);
        }

        private final String s;

        private BinOp(String s)
        {
            this.s = s;
        }
    }

    private static abstract class Constraint
    {
        boolean permits(AlgorithmParameters parameters)
        {
            return true;
        }

        boolean permits(Key key)
        {
            return true;
        }
    }

    private static class DisabledConstraint
        extends Constraint
    {
        static final DisabledConstraint INSTANCE = new DisabledConstraint();

        private DisabledConstraint()
        {
        }

        @Override
        public boolean permits(Key key)
        {
            return false;
        }
    }

    private static class KeySizeConstraint
        extends Constraint
    {
        private static int getKeySize(AlgorithmParameters parameters)
        {
            String algorithm = parameters.getAlgorithm();
            if ("EC".equals(algorithm))
            {
                try
                {
                    ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
                    if (null != spec)
                    {
                        return spec.getOrder().bitLength();
                    }
                }
                catch (InvalidParameterSpecException e)
                {
                }
            }
            else if ("DiffieHellman".equals(algorithm))
            {
                try
                {
                    DHParameterSpec spec = parameters.getParameterSpec(DHParameterSpec.class);
                    if (null != spec)
                    {
                        return spec.getP().bitLength();
                    }
                }
                catch (InvalidParameterSpecException e)
                {
                }
            }

            return -1;
        }

        private static int getKeySize(Key key)
        {
            if (key instanceof RSAKey)
            {
                RSAKey rsaKey = (RSAKey)key;
                return rsaKey.getModulus().bitLength();
            }
            else if (key instanceof ECKey)
            {
                ECKey ecKey = (ECKey)key;
                return ecKey.getParams().getOrder().bitLength();
            }
            else if (key instanceof DSAKey)
            {
                DSAKey dsaKey = (DSAKey)key;
                DSAParams dsaParams = dsaKey.getParams();
                if (null != dsaParams)
                {
                    return dsaParams.getP().bitLength();
                }
            }
            else if (key instanceof DHKey)
            {
                DHKey dhKey = (DHKey)key;
                return dhKey.getParams().getP().bitLength();
            }
            else if (key instanceof SecretKey)
            {
                SecretKey secretKey = (SecretKey)key;
                String format = secretKey.getFormat();
                if ("RAW".equals(format))
                {
                    byte[] raw = secretKey.getEncoded();
                    if (null != raw)
                    {
                        int byteLen = raw.length;
                        return byteLen > (Integer.MAX_VALUE >>> 3) ? 0 : 8 * raw.length;
                    }
                }
            }

            return -1;
        }

        private final BinOp op;
        private final int constraint;

        KeySizeConstraint(BinOp op, int constraint)
        {
            this.op = op;
            this.constraint = constraint;
        }

        @Override
        boolean permits(AlgorithmParameters parameters)
        {
            return checkKeySize(getKeySize(parameters));
        }

        @Override
        boolean permits(Key key)
        {
            return checkKeySize(getKeySize(key));
        }

        private boolean checkKeySize(int keySize)
        {
            if (keySize < 1)
            {
                return keySize < 0;
            }

            return !BinOp.eval(op, keySize, constraint); 
        }
    }
}
