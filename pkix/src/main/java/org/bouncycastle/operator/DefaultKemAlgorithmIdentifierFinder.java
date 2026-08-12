package org.bouncycastle.operator;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Strings;

/**
 * Default implementation of {@link KemAlgorithmIdentifierFinder}, returning the
 * {@code AlgorithmIdentifier} used to name a key encapsulation mechanism.
 * <p>
 * None of the KEMs named here take algorithm parameters - each parameter set has
 * its own OID - so every identifier this returns has an absent
 * {@code parameters} field, matching what the provider emits in a
 * SubjectPublicKeyInfo for these algorithms. On the receiving side compare with
 * {@link AlgorithmIdentifier#areEquivalent(AlgorithmIdentifier, AlgorithmIdentifier)}
 * rather than {@code equals}, so that a peer spelling the same algorithm with an
 * explicit NULL still matches.
 * </p><p>
 * Names are matched without regard to case and are the canonical ones the
 * matching lightweight parameter class uses - {@code MLKEMParameters.getName()},
 * {@code FrodoKEMParameters.getName()}, {@code CMCEParameters.getName()} - which
 * are also the names the BouncyCastle provider registers the algorithms under.
 * Coverage is restricted to the standardised assignments: BouncyCastle's own
 * pre-standard arcs for FrodoKEM and Classic McEliece are deliberately absent,
 * as those parameters are to be phased out.
 * </p>
 */
public class DefaultKemAlgorithmIdentifierFinder
    implements KemAlgorithmIdentifierFinder
{
    private static Map algorithms = new HashMap();

    static
    {
        // ML-KEM (FIPS 203)
        addAlgorithm("ML-KEM-512", NISTObjectIdentifiers.id_alg_ml_kem_512);
        addAlgorithm("ML-KEM-768", NISTObjectIdentifiers.id_alg_ml_kem_768);
        addAlgorithm("ML-KEM-1024", NISTObjectIdentifiers.id_alg_ml_kem_1024);

        // FrodoKEM, ISO/IEC 18033-2 arc
        addAlgorithm("frodokem976shake", ISOIECObjectIdentifiers.frodokem976_shake);
        addAlgorithm("frodokem1344shake", ISOIECObjectIdentifiers.frodokem1344_shake);
        addAlgorithm("efrodokem976shake", ISOIECObjectIdentifiers.efrodokem976_shake);
        addAlgorithm("efrodokem1344shake", ISOIECObjectIdentifiers.efrodokem1344_shake);
        addAlgorithm("frodokem976aes", ISOIECObjectIdentifiers.frodokem976_aes);
        addAlgorithm("frodokem1344aes", ISOIECObjectIdentifiers.frodokem1344_aes);
        addAlgorithm("efrodokem976aes", ISOIECObjectIdentifiers.efrodokem976_aes);
        addAlgorithm("efrodokem1344aes", ISOIECObjectIdentifiers.efrodokem1344_aes);

        // Classic McEliece, ISO/IEC 18033-2 arc
        addAlgorithm("mceliece460896", ISOIECObjectIdentifiers.mceliece460896);
        addAlgorithm("mceliece460896f", ISOIECObjectIdentifiers.mceliece460896f);
        addAlgorithm("mceliece460896pc", ISOIECObjectIdentifiers.mceliece460896pc);
        addAlgorithm("mceliece460896pcf", ISOIECObjectIdentifiers.mceliece460896pcf);
        addAlgorithm("mceliece6688128", ISOIECObjectIdentifiers.mceliece6688128);
        addAlgorithm("mceliece6688128f", ISOIECObjectIdentifiers.mceliece6688128f);
        addAlgorithm("mceliece6688128pc", ISOIECObjectIdentifiers.mceliece6688128pc);
        addAlgorithm("mceliece6688128pcf", ISOIECObjectIdentifiers.mceliece6688128pcf);
        addAlgorithm("mceliece6960119", ISOIECObjectIdentifiers.mceliece6960119);
        addAlgorithm("mceliece6960119f", ISOIECObjectIdentifiers.mceliece6960119f);
        addAlgorithm("mceliece6960119pc", ISOIECObjectIdentifiers.mceliece6960119pc);
        addAlgorithm("mceliece6960119pcf", ISOIECObjectIdentifiers.mceliece6960119pcf);
        addAlgorithm("mceliece8192128", ISOIECObjectIdentifiers.mceliece8192128);
        addAlgorithm("mceliece8192128f", ISOIECObjectIdentifiers.mceliece8192128f);
        addAlgorithm("mceliece8192128pc", ISOIECObjectIdentifiers.mceliece8192128pc);
        addAlgorithm("mceliece8192128pcf", ISOIECObjectIdentifiers.mceliece8192128pcf);
    }

    private static void addAlgorithm(String algorithmName, ASN1ObjectIdentifier algOid)
    {
        algorithms.put(Strings.toUpperCase(algorithmName), algOid);
    }

    public boolean hasAlgorithm(String kemAlgName)
    {
        return algorithms.containsKey(Strings.toUpperCase(kemAlgName));
    }

    public AlgorithmIdentifier find(String kemAlgName)
    {
        ASN1ObjectIdentifier kemOID = (ASN1ObjectIdentifier)algorithms.get(Strings.toUpperCase(kemAlgName));
        if (kemOID == null)
        {
            throw new IllegalArgumentException("Unknown KEM algorithm requested: " + kemAlgName);
        }

        return new AlgorithmIdentifier(kemOID);
    }
}
