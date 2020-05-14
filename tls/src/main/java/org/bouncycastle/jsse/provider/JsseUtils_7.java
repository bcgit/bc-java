package org.bouncycastle.jsse.provider;

import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;

abstract class JsseUtils_7
    extends JsseUtils
{
    static final Set<CryptoPrimitive> KEY_AGREEMENT_CRYPTO_PRIMITIVES =
        Collections.unmodifiableSet(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT));
    static final Set<CryptoPrimitive> KEY_ENCAPSULATION_CRYPTO_PRIMITIVES =
        Collections.unmodifiableSet(EnumSet.of(CryptoPrimitive.KEY_ENCAPSULATION));
    static final Set<CryptoPrimitive> SIGNATURE_CRYPTO_PRIMITIVES =
        Collections.unmodifiableSet(EnumSet.of(CryptoPrimitive.SIGNATURE));

    static final AlgorithmConstraints DEFAULT_ALGORITHM_CONSTRAINTS = new ExportAlgorithmConstraints(
        ProvAlgorithmConstraints.DEFAULT);

    static class ExportAlgorithmConstraints implements AlgorithmConstraints
    {
        private final BCAlgorithmConstraints constraints;

        ExportAlgorithmConstraints(BCAlgorithmConstraints constraints)
        {
            this.constraints = constraints;
        }

        public boolean permits(Set<CryptoPrimitive> primitives, Key key)
        {
            return constraints.permits(importCryptoPrimitives(primitives), key);
        }

        public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters)
        {
            return constraints.permits(importCryptoPrimitives(primitives), algorithm, parameters);
        }

        public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key,
            AlgorithmParameters parameters)
        {
            return constraints.permits(importCryptoPrimitives(primitives), algorithm, key, parameters);
        }

        BCAlgorithmConstraints unwrap()
        {
            return constraints;
        }
    }

    static class ImportAlgorithmConstraints implements BCAlgorithmConstraints
    {
        private final AlgorithmConstraints constraints;

        ImportAlgorithmConstraints(AlgorithmConstraints constraints)
        {
            this.constraints = constraints;
        }

        public boolean permits(Set<BCCryptoPrimitive> primitives, Key key)
        {
            return constraints.permits(exportCryptoPrimitives(primitives), key);
        }

        public boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters)
        {
            return constraints.permits(exportCryptoPrimitives(primitives), algorithm, parameters);
        }

        public boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, Key key,
            AlgorithmParameters parameters)
        {
            return constraints.permits(exportCryptoPrimitives(primitives), algorithm, key, parameters);
        }

        AlgorithmConstraints unwrap()
        {
            return constraints;
        }
    }

    static AlgorithmConstraints exportAlgorithmConstraints(BCAlgorithmConstraints constraints)
    {
        if (ProvAlgorithmConstraints.DEFAULT == constraints)
        {
            return DEFAULT_ALGORITHM_CONSTRAINTS;
        }

        if (constraints == null)
        {
            return null;
        }

        if (constraints instanceof ImportAlgorithmConstraints)
        {
            return ((ImportAlgorithmConstraints)constraints).unwrap();
        }

        return new ExportAlgorithmConstraints(constraints);
    }

    /*
     * NOTE: Return type is Object to isolate callers from JDK 7 type
     */
    static Object exportAlgorithmConstraintsDynamic(BCAlgorithmConstraints constraints)
    {
        return exportAlgorithmConstraints(constraints);
    }

    static CryptoPrimitive exportCryptoPrimitive(BCCryptoPrimitive primitive)
    {
        switch (primitive)
        {
        case MESSAGE_DIGEST:
            return CryptoPrimitive.MESSAGE_DIGEST;
        case SECURE_RANDOM:
            return CryptoPrimitive.SECURE_RANDOM;
        case BLOCK_CIPHER:
            return CryptoPrimitive.BLOCK_CIPHER;
        case STREAM_CIPHER:
            return CryptoPrimitive.STREAM_CIPHER;
        case MAC:
            return CryptoPrimitive.MAC;
        case KEY_WRAP:
            return CryptoPrimitive.KEY_WRAP;
        case PUBLIC_KEY_ENCRYPTION:
            return CryptoPrimitive.PUBLIC_KEY_ENCRYPTION;
        case SIGNATURE:
            return CryptoPrimitive.SIGNATURE;
        case KEY_ENCAPSULATION:
            return CryptoPrimitive.KEY_ENCAPSULATION;
        case KEY_AGREEMENT:
            return CryptoPrimitive.KEY_AGREEMENT;
        default:
            return null;
        }
    }

    static Set<CryptoPrimitive> exportCryptoPrimitives(Set<BCCryptoPrimitive> primitives)
    {
        if (SIGNATURE_CRYPTO_PRIMITIVES_BC == primitives)
        {
            return SIGNATURE_CRYPTO_PRIMITIVES;
        }
        if (KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC == primitives)
        {
            return KEY_AGREEMENT_CRYPTO_PRIMITIVES;
        }
        if (KEY_ENCAPSULATION_CRYPTO_PRIMITIVES_BC == primitives)
        {
            return KEY_ENCAPSULATION_CRYPTO_PRIMITIVES;
        }

        HashSet<CryptoPrimitive> result = new HashSet<CryptoPrimitive>();
        for (BCCryptoPrimitive primitive : primitives)
        {
            result.add(exportCryptoPrimitive(primitive));
        }
        return result;
    }

    static BCAlgorithmConstraints importAlgorithmConstraints(AlgorithmConstraints constraints)
    {
        if (null == constraints)
        {
            return null;
        }

        if (constraints instanceof ExportAlgorithmConstraints)
        {
            return ((ExportAlgorithmConstraints)constraints).unwrap();
        }

        return new ImportAlgorithmConstraints(constraints);
    }

    /*
     * NOTE: Argument type is Object to isolate callers from JDK 7 type
     */
    static BCAlgorithmConstraints importAlgorithmConstraintsDynamic(Object constraints)
    {
        return importAlgorithmConstraints((AlgorithmConstraints)constraints);
    }

    static BCCryptoPrimitive importCryptoPrimitive(CryptoPrimitive primitive)
    {
        switch (primitive)
        {
        case MESSAGE_DIGEST:
            return BCCryptoPrimitive.MESSAGE_DIGEST;
        case SECURE_RANDOM:
            return BCCryptoPrimitive.SECURE_RANDOM;
        case BLOCK_CIPHER:
            return BCCryptoPrimitive.BLOCK_CIPHER;
        case STREAM_CIPHER:
            return BCCryptoPrimitive.STREAM_CIPHER;
        case MAC:
            return BCCryptoPrimitive.MAC;
        case KEY_WRAP:
            return BCCryptoPrimitive.KEY_WRAP;
        case PUBLIC_KEY_ENCRYPTION:
            return BCCryptoPrimitive.PUBLIC_KEY_ENCRYPTION;
        case SIGNATURE:
            return BCCryptoPrimitive.SIGNATURE;
        case KEY_ENCAPSULATION:
            return BCCryptoPrimitive.KEY_ENCAPSULATION;
        case KEY_AGREEMENT:
            return BCCryptoPrimitive.KEY_AGREEMENT;
        default:
            return null;
        }
    }

    static Set<BCCryptoPrimitive> importCryptoPrimitives(Set<CryptoPrimitive> primitives)
    {
        if (SIGNATURE_CRYPTO_PRIMITIVES == primitives)
        {
            return SIGNATURE_CRYPTO_PRIMITIVES_BC;
        }
        if (KEY_AGREEMENT_CRYPTO_PRIMITIVES == primitives)
        {
            return KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;
        }
        if (KEY_ENCAPSULATION_CRYPTO_PRIMITIVES == primitives)
        {
            return KEY_ENCAPSULATION_CRYPTO_PRIMITIVES_BC;
        }

        HashSet<BCCryptoPrimitive> result = new HashSet<BCCryptoPrimitive>();
        for (CryptoPrimitive primitive : primitives)
        {
            result.add(importCryptoPrimitive(primitive));
        }
        return result;
    }
}
