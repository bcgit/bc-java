package org.bouncycastle.pqc.crypto.util;

import java.io.IOException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;

/**
 * Factory to create ASN.1 subject public key info objects from lightweight public keys.
 */
public class SubjectPublicKeyInfoFactory
{
    private SubjectPublicKeyInfoFactory()
    {

    }

    /**
     * Create a SubjectPublicKeyInfo public key.
     *
     * @param publicKey the key to be encoded into the info object.
     * @return a SubjectPublicKeyInfo representing the key.
     * @throws java.io.IOException on an error encoding the key
     */
    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
        throws IOException
    {
        if (publicKey instanceof QTESLAPublicKeyParameters)
        {
            QTESLAPublicKeyParameters keyParams = (QTESLAPublicKeyParameters)publicKey;
            AlgorithmIdentifier algorithmIdentifier = Utils.qTeslaLookupAlgID(keyParams.getSecurityCategory());

            return new SubjectPublicKeyInfo(algorithmIdentifier, keyParams.getPublicData());
        }
        else if (publicKey instanceof SPHINCSPublicKeyParameters)
        {
            SPHINCSPublicKeyParameters params = (SPHINCSPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256,
                new SPHINCS256KeyParams(Utils.sphincs256LookupTreeAlgID(params.getTreeDigest())));
            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getKeyData());
        }
        else if (publicKey instanceof NHPublicKeyParameters)
        {
            NHPublicKeyParameters params = (NHPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);
            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getPubData());
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }
}
