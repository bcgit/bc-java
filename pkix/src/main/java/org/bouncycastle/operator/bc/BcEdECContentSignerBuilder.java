package org.bouncycastle.operator.bc;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.operator.OperatorCreationException;

public class BcEdECContentSignerBuilder
    extends BcContentSignerBuilder
{
    public BcEdECContentSignerBuilder(AlgorithmIdentifier sigAlgId)
    {
        super(sigAlgId, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512));
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
    {
        if (sigAlgId.getAlgorithm().equals(EdECObjectIdentifiers.id_Ed25519))
        {
            return new Ed25519Signer();
        }

        throw new IllegalStateException("unknown signature type");
    }
}
