package org.bouncycastle.operator;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Integers;

/**
 * Look up provider for encapsulation lengths produced be KEM algorithms
 */
public class DefaultKemEncapsulationLengthProvider
    implements KemEncapsulationLengthProvider
{
    private static Map<ASN1ObjectIdentifier, Integer> kemEncapsulationLengths = new HashMap<ASN1ObjectIdentifier, Integer>();

    static
    {
        kemEncapsulationLengths.put(NISTObjectIdentifiers.id_alg_ml_kem_512, Integers.valueOf(768));
        kemEncapsulationLengths.put(NISTObjectIdentifiers.id_alg_ml_kem_768, Integers.valueOf(1088));
        kemEncapsulationLengths.put(NISTObjectIdentifiers.id_alg_ml_kem_1024, Integers.valueOf(1568));

        kemEncapsulationLengths.put(BCObjectIdentifiers.ntruhps2048509, Integers.valueOf(699));
        kemEncapsulationLengths.put(BCObjectIdentifiers.ntruhps2048677, Integers.valueOf(930));
        kemEncapsulationLengths.put(BCObjectIdentifiers.ntruhps4096821, Integers.valueOf(1230));
        kemEncapsulationLengths.put(BCObjectIdentifiers.ntruhps40961229, Integers.valueOf(1842));
        kemEncapsulationLengths.put(BCObjectIdentifiers.ntruhrss701, Integers.valueOf(1138));
        kemEncapsulationLengths.put(BCObjectIdentifiers.ntruhrss1373, Integers.valueOf(2401));

        kemEncapsulationLengths.put(BCObjectIdentifiers.hqc128, Integers.valueOf(4433));
        kemEncapsulationLengths.put(BCObjectIdentifiers.hqc192, Integers.valueOf(8978));
        kemEncapsulationLengths.put(BCObjectIdentifiers.hqc256, Integers.valueOf(14421));

        // FrodoKEM (ISO/IEC 18033-2 arc); ciphertext sizes are per parameter set, independent of AES/SHAKE
        kemEncapsulationLengths.put(ISOIECObjectIdentifiers.frodokem976_shake, Integers.valueOf(15792));
        kemEncapsulationLengths.put(ISOIECObjectIdentifiers.frodokem976_aes, Integers.valueOf(15792));
        kemEncapsulationLengths.put(ISOIECObjectIdentifiers.frodokem1344_shake, Integers.valueOf(21696));
        kemEncapsulationLengths.put(ISOIECObjectIdentifiers.frodokem1344_aes, Integers.valueOf(21696));
        kemEncapsulationLengths.put(ISOIECObjectIdentifiers.efrodokem976_shake, Integers.valueOf(15744));
        kemEncapsulationLengths.put(ISOIECObjectIdentifiers.efrodokem976_aes, Integers.valueOf(15744));
        kemEncapsulationLengths.put(ISOIECObjectIdentifiers.efrodokem1344_shake, Integers.valueOf(21632));
        kemEncapsulationLengths.put(ISOIECObjectIdentifiers.efrodokem1344_aes, Integers.valueOf(21632));
    }

    public int getEncapsulationLength(AlgorithmIdentifier kemAlgorithm)
    {
        return ((Integer)kemEncapsulationLengths.get(kemAlgorithm.getAlgorithm())).intValue();
    }
}
