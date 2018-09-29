package org.bouncycastle.pqc.jcajce.provider.qtesla;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.util.Integers;

class KeyUtils
{
    static final AlgorithmIdentifier AlgID_qTESLA_I = new AlgorithmIdentifier(PQCObjectIdentifiers.qTESLA_I);
    static final AlgorithmIdentifier AlgID_qTESLA_III_size = new AlgorithmIdentifier(PQCObjectIdentifiers.qTESLA_III_size);
    static final AlgorithmIdentifier AlgID_qTESLA_III_speed = new AlgorithmIdentifier(PQCObjectIdentifiers.qTESLA_III_speed);
    static final AlgorithmIdentifier AlgID_qTESLA_p_I = new AlgorithmIdentifier(PQCObjectIdentifiers.qTESLA_p_I);
    static final AlgorithmIdentifier AlgID_qTESLA_p_III = new AlgorithmIdentifier(PQCObjectIdentifiers.qTESLA_p_III);

    static final Map categories = new HashMap();

    static
    {
        categories.put(PQCObjectIdentifiers.qTESLA_I, Integers.valueOf(QTESLASecurityCategory.HEURISTIC_I));
        categories.put(PQCObjectIdentifiers.qTESLA_III_size, Integers.valueOf(QTESLASecurityCategory.HEURISTIC_III_SIZE));
        categories.put(PQCObjectIdentifiers.qTESLA_III_speed, Integers.valueOf(QTESLASecurityCategory.HEURISTIC_III_SPEED));
        categories.put(PQCObjectIdentifiers.qTESLA_p_I, Integers.valueOf(QTESLASecurityCategory.PROVABLY_SECURE_I));
        categories.put(PQCObjectIdentifiers.qTESLA_p_III, Integers.valueOf(QTESLASecurityCategory.PROVABLY_SECURE_III));
    }

    static int lookupSecurityCatergory(AlgorithmIdentifier algorithm)
    {
        return ((Integer)categories.get(algorithm.getAlgorithm())).intValue();
    }

    static AlgorithmIdentifier lookupAlgID(int securityCategory)
    {
        switch (securityCategory)
        {
        case QTESLASecurityCategory.HEURISTIC_I:
            return AlgID_qTESLA_I;
        case QTESLASecurityCategory.HEURISTIC_III_SIZE:
            return AlgID_qTESLA_III_size;
        case QTESLASecurityCategory.HEURISTIC_III_SPEED:
            return AlgID_qTESLA_III_speed;
        case QTESLASecurityCategory.PROVABLY_SECURE_I:
            return AlgID_qTESLA_p_I;
        case QTESLASecurityCategory.PROVABLY_SECURE_III:
            return AlgID_qTESLA_p_III;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }
}
