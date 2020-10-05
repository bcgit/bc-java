package org.bouncycastle.cert.crmf;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.POPOSigningKeyInput;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;

public class ProofOfPossessionSigningKeyBuilder
{
    private CertRequest certRequest;
    private SubjectPublicKeyInfo pubKeyInfo;
    private GeneralName name;
    private PKMACValue publicKeyMAC;

    public ProofOfPossessionSigningKeyBuilder(CertRequest certRequest)
    {
        this.certRequest = certRequest;
    }


    public ProofOfPossessionSigningKeyBuilder(SubjectPublicKeyInfo pubKeyInfo)
    {
        this.pubKeyInfo = pubKeyInfo;
    }

    public ProofOfPossessionSigningKeyBuilder setSender(GeneralName name)
    {
        this.name = name;

        return this;
    }

    public ProofOfPossessionSigningKeyBuilder setPublicKeyMac(PKMACValueGenerator generator, char[] password)
        throws CRMFException
    {
        this.publicKeyMAC = generator.generate(password, pubKeyInfo);

        return this;
    }

    public POPOSigningKey build(ContentSigner signer)
    {
        if (name != null && publicKeyMAC != null)
        {
            throw new IllegalStateException("name and publicKeyMAC cannot both be set.");
        }

        POPOSigningKeyInput popo;

        if (certRequest != null)
        {
            popo = null;

            CRMFUtil.derEncodeToStream(certRequest, signer.getOutputStream());
        }
        else if (name != null)
        {
            popo = new POPOSigningKeyInput(name, pubKeyInfo);

            CRMFUtil.derEncodeToStream(popo, signer.getOutputStream());
        }
        else
        {
            popo = new POPOSigningKeyInput(publicKeyMAC, pubKeyInfo);

            CRMFUtil.derEncodeToStream(popo, signer.getOutputStream());
        }

        return new POPOSigningKey(popo, signer.getAlgorithmIdentifier(), new DERBitString(signer.getSignature()));
    }
}
