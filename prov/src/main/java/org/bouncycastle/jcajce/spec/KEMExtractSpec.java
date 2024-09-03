package org.bouncycastle.jcajce.spec;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.Arrays;

public class KEMExtractSpec
    extends KEMKDFSpec
    implements AlgorithmParameterSpec
{
    private static final byte[] EMPTY_OTHER_INFO = new byte[0];
    private static AlgorithmIdentifier DefKdf = new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

    private final PrivateKey privateKey;
    private final byte[] encapsulation;

    private KEMExtractSpec(PrivateKey privateKey, byte[] encapsulation, String keyAlgorithmName, int keySizeInBits, AlgorithmIdentifier kdfAlgorithm, byte[] otherInfo)
    {
        super(kdfAlgorithm, otherInfo, keyAlgorithmName, keySizeInBits);

        this.privateKey = privateKey;
        this.encapsulation = Arrays.clone(encapsulation);
    }

    public KEMExtractSpec(PrivateKey privateKey, byte[] encapsulation, String keyAlgorithmName)
    {
        this(privateKey, encapsulation, keyAlgorithmName, 256);
    }

    public KEMExtractSpec(PrivateKey privateKey, byte[] encapsulation, String keyAlgorithmName, int keySizeInBits)
    {
        this(privateKey, encapsulation, keyAlgorithmName, keySizeInBits, DefKdf, EMPTY_OTHER_INFO);
    }

    public byte[] getEncapsulation()
    {
        return Arrays.clone(encapsulation);
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }
}
