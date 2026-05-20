package org.bouncycastle.operator.bc;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.operator.OperatorCreationException;

public class BcRSAContentSignerBuilder
    extends BcContentSignerBuilder
{
    public BcRSAContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
    {
        super(sigAlgId, digAlgId);
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
    {
        // RSASSA-PSS (RFC 8017) and PKCS#1 v1.5 are wire-incompatible
        // signature schemes — using RSADigestSigner for an id-RSASSA-PSS
        // sigAlgId would produce signatures that no PSS verifier will
        // accept (github #721). Dispatch on the OID so the lightweight
        // path matches what the JCE Signature.getInstance("RSASSA-PSS")
        // path does.
        if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgId.getAlgorithm()))
        {
            return BcRsaPssUtil.createSigner(sigAlgId, digestProvider);
        }

        Digest dig = digestProvider.get(digAlgId);

        return new RSADigestSigner(dig);
    }
}
