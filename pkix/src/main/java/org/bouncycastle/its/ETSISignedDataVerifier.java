package org.bouncycastle.its;

import java.io.OutputStream;


import org.bouncycastle.its.operator.ECDSAEncoder;
import org.bouncycastle.its.operator.ETSIDataVerifierProvider;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.its.ieee1609dot2.SignedData;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import org.bouncycastle.operator.ContentVerifier;

public class ETSISignedDataVerifier
{
    private final SignedData signedData;

    public ETSISignedDataVerifier(SignedData signedData)
    {
        this.signedData = signedData;
    }

    /**
     * Verify signature is valid with respect to the supplied public key.
     * Contextual verification, ie "is this SignedData what you are expecting?" type checking needs to be done
     * by the caller.
     * @param publicKey The public key.
     * @return true if the signature was valid.
     * @throws Exception
     */
    public boolean signatureValid(ETSIDataVerifierProvider verifierProvider)
        throws Exception
    {
        Signature sig = signedData.getSignature();
        ContentVerifier verifier = verifierProvider.getContentVerifier(sig.getChoice());
        OutputStream os = verifier.getOutputStream();
        os.write(OEREncoder.toByteArray(signedData.getTbsData(), IEEE1609dot2.ToBeSignedData.build()));
        os.close();

        return verifier.verify(ECDSAEncoder.toX962(signedData.getSignature()));

    }

}
