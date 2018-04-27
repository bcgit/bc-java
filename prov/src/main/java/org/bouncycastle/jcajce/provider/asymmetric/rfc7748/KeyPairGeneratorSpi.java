/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package org.bouncycastle.jcajce.provider.asymmetric.rfc7748;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;

import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.spec.RFC7748GenParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.spec.RFC7748NamedCurveSpec;
import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.spec.RFC7748NamedCurveTable;
import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.spec.RFC7748ParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.spec.RFC7748PrivateKeySpec;
import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.spec.RFC7748PublicKeySpec;

/**
 *  Default keysize is 256 (Ed25519)
 */
public class KeyPairGeneratorSpi extends java.security.KeyPairGenerator {
    private static final int DEFAULT_KEYSIZE = 256;
    protected RFC7748ParameterSpec paramSpec;
    protected SecureRandom random;
    protected boolean initialized;

    private static final Hashtable<Integer, AlgorithmParameterSpec> paramsByKeySize;

    static {
        paramsByKeySize = new Hashtable<Integer, AlgorithmParameterSpec>();

        paramsByKeySize.put(Integer.valueOf(256), new RFC7748GenParameterSpec("Ed25519"));
    }

    public KeyPairGeneratorSpi(String algorithmName)
    {
        super(algorithmName);
    }

    public void initialize(int keysize, SecureRandom random) {
        AlgorithmParameterSpec paramSpec = paramsByKeySize.get(Integer.valueOf(keysize));
        if (paramSpec == null)
            throw new InvalidParameterException("unknown key type.");
        try {
            initialize(paramSpec, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException("key type not configurable.");
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params instanceof RFC7748ParameterSpec) {
            paramSpec = (RFC7748ParameterSpec) params;
        } else if (params instanceof RFC7748GenParameterSpec) {
            paramSpec = createNamedCurveSpec(((RFC7748GenParameterSpec) params).getName());
        } else
            throw new InvalidAlgorithmParameterException("parameter object not a RFC7748ParameterSpec");

        this.random = random;
        initialized = true;
    }

    public KeyPair generateKeyPair() {
        if (!initialized)
            initialize(DEFAULT_KEYSIZE, new SecureRandom());

        byte[] seed = new byte[paramSpec.getCurve().getField().getb()/8];
        random.nextBytes(seed);

        RFC7748PrivateKeySpec privKey = new RFC7748PrivateKeySpec(seed, paramSpec);
        RFC7748PublicKeySpec pubKey = new RFC7748PublicKeySpec(privKey.getA(), paramSpec);

        return new KeyPair(new RFC7748PublicKey(pubKey), new RFC7748PrivateKey(privKey));
    }

    /**
     * Create an RFC7748NamedCurveSpec from the provided curve name. The current
     * implementation fetches the pre-created curve spec from a table.
     * @param curveName the RFC7748 named curve.
     * @return the specification for the named curve.
     * @throws InvalidAlgorithmParameterException if the named curve is unknown.
     */
    protected RFC7748NamedCurveSpec createNamedCurveSpec(String curveName) throws InvalidAlgorithmParameterException {
        RFC7748NamedCurveSpec spec = RFC7748NamedCurveTable.getByName(curveName);
        if (spec == null) {
            throw new InvalidAlgorithmParameterException("unknown curve name: " + curveName);
        }
        return spec;
    }
    
    public static class Ed25519 extends KeyPairGeneratorSpi
    {
        public Ed25519()
        {
            super("Ed25519");
            paramSpec = RFC7748NamedCurveTable.getByName("Ed25519");
            random = new SecureRandom();
            initialized = true;
        }
    }

}
