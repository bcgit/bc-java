package org.bouncycastle.crypto.constraints;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.params.CramerShoupKeyParameters;
import org.bouncycastle.crypto.params.CramerShoupParameters;
import org.bouncycastle.crypto.params.DHKeyParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.ElGamalKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.GOST3410KeyParameters;
import org.bouncycastle.crypto.params.GOST3410Parameters;
import org.bouncycastle.crypto.params.NaccacheSternKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Strings;

public class ConstraintUtils
{
    /**
     * The service names under which the quantum-vulnerable public-key algorithms report to the
     * constraints framework (upper-cased).
     */
    private static final Set<String> QUANTUM_VULNERABLE_SERVICES = new HashSet<String>();

    static
    {
        String[] names = new String[]{
            "RSA", "RSAKem", "RSAKeyGen",
            "DSA", "DSAKeyGen",
            "DH", "DHU", "DHB", "DHKeyGen", "DHBasicKeyGen", "MQV",
            "ECDH", "ECCDH", "ECCDHU", "ECMQV", "ECDSA", "ECNR", "ECGOST3410", "ECIESKem", "ECVKO", "ECCSI", "ECKeyGen",
            "GOST3410", "GOST3410KeyGen",
            "SM2", "SM2KE", "SM2KeyGen",
            "X25519", "X25519KeyGen", "X448", "X448KeyGen",
            "Ed25519", "Ed25519KeyGen", "Ed448", "Ed448KeyGen",
            "ElGamalKeyGen", "CramerShoup", "CramerShoupKeyGen",
            "NaccacheStern", "NaccacheStern KeyGen",
            "DSTU4145", "BIP340"
        };

        for (int i = 0; i != names.length; i++)
        {
            QUANTUM_VULNERABLE_SERVICES.add(Strings.toUpperCase(names[i]));
        }
    }

    /**
     * Return true if the service is one of the quantum-vulnerable public-key algorithms: the
     * integer factorisation and discrete logarithm schemes NIST IR 8547 deprecates after 2030 and
     * disallows after 2035 (RSA, DSA, DH/MQV, ECDSA/ECDH and their variants, EdDSA, X25519/X448,
     * ElGamal, Cramer-Shoup, Naccache-Stern and the KEMs and key agreements built on them). The decision is made on the key or
     * domain parameters the service reports where it reports any, and otherwise on its name. The
     * post-quantum algorithms and symmetric services are never quantum-vulnerable.
     *
     * @param service the service properties passed to the constraint.
     * @return true if the service relies on a quantum-vulnerable public-key algorithm, false otherwise.
     */
    public static boolean isQuantumVulnerable(CryptoServiceProperties service)
    {
        Object params = service.getParams();

        if (params instanceof RSAKeyParameters
            || params instanceof DSAKeyParameters || params instanceof DSAParameters
            || params instanceof DHKeyParameters || params instanceof DHParameters
            || params instanceof ECKeyParameters || params instanceof ECDomainParameters
            || params instanceof ElGamalKeyParameters || params instanceof ElGamalParameters
            || params instanceof GOST3410KeyParameters || params instanceof GOST3410Parameters
            || params instanceof CramerShoupKeyParameters || params instanceof CramerShoupParameters
            || params instanceof NaccacheSternKeyParameters
            || params instanceof X25519PrivateKeyParameters || params instanceof X25519PublicKeyParameters
            || params instanceof X448PrivateKeyParameters || params instanceof X448PublicKeyParameters
            || params instanceof Ed25519PrivateKeyParameters || params instanceof Ed25519PublicKeyParameters
            || params instanceof Ed448PrivateKeyParameters || params instanceof Ed448PublicKeyParameters)
        {
            return true;
        }

        String name = service.getServiceName();

        return name != null && QUANTUM_VULNERABLE_SERVICES.contains(Strings.toUpperCase(name));
    }

    /**
     * Return the bits of security for the passed in RSA modulus or DH/DSA group value.
     *
     * @param p a modulus or group value
     * @return the security strength in bits.
     */
    public static int bitsOfSecurityFor(BigInteger p)
    {
        return bitsOfSecurityForFF(p.bitLength());
    }

    /**
     * Return the bits of security for the passed in Elliptic Curve.
     *
     * @param curve the ECCurve of interest.
     * @return the security strength in bits.
     */
    public static int bitsOfSecurityFor(ECCurve curve)
    {
        int sBits = (curve.getFieldSize() + 1) / 2;

        return (sBits > 256) ? 256 : sBits;
    }

    public static int bitsOfSecurityForFF(int strength)
    {
        if (strength >= 2048)
        {
            return (strength >= 3072) ?
                        ((strength >= 7680) ?
                            ((strength >= 15360) ? 256
                            : 192)
                        : 128)
                   : 112;
        }

        return (strength >= 1024) ? 80 : 20;      // TODO: possibly a bit harsh...
    }
}
