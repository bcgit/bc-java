package org.bouncycastle.its;

import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.its.operator.ETSIDataSigner;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.its.ieee1609dot2.Certificate;
import org.bouncycastle.oer.its.ieee1609dot2.SequenceOfCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.SignedData;
import org.bouncycastle.oer.its.ieee1609dot2.SignerIdentifier;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedData;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;

public class ETSISignedDataBuilder
{
    private final ToBeSignedData toBeSignedData;
    private static final Element def = IEEE1609dot2.ToBeSignedData.build();

    public ETSISignedDataBuilder(ToBeSignedData toBeSignedData)
    {
        this.toBeSignedData = toBeSignedData;
    }

    /**
     * Self signed
     *
     * @param signer
     * @return
     */
    public ETSISignedData build(ETSIDataSigner signer)
    {
        write(signer.getOutputStream(), OEREncoder.toByteArray(toBeSignedData, def));

        return new ETSISignedData(SignedData.builder()
            .setHashId(ITSAlgorithmUtils.getHashAlgorithm(signer.getDigestAlgorithm().getAlgorithm()))
            .setTbsData(toBeSignedData)
            .setSigner(SignerIdentifier.builder().self().build())
            .setSignature(signer.getSignature()).build());
    }

    /**
     * Ceritificate
     *
     * @param signer
     * @param certificateList
     * @return
     */
    public ETSISignedData build(ETSIDataSigner signer, List<ITSCertificate> certificateList)
    {
        write(signer.getOutputStream(), OEREncoder.toByteArray(toBeSignedData, def));

        List<Certificate> certificates = new ArrayList<Certificate>();
        for (ITSCertificate certificate : certificateList)
        {
            certificates.add(Certificate.getInstance(certificate.toASN1Structure()));
        }

        return new ETSISignedData( SignedData.builder()
            .setHashId(ITSAlgorithmUtils.getHashAlgorithm(signer.getDigestAlgorithm().getAlgorithm()))
            .setTbsData(toBeSignedData)
            .setSigner(SignerIdentifier.builder().certificate(new SequenceOfCertificate(certificates)).build())
            .setSignature(signer.getSignature()).build());
    }

    /**
     * Hash id
     *
     * @param signer
     * @param identifier
     * @return
     */
    public ETSISignedData build(ETSIDataSigner signer, HashedId8 identifier)
    {

        write(signer.getOutputStream(), OEREncoder.toByteArray(toBeSignedData, def));

        return new ETSISignedData(SignedData.builder()
            .setHashId(ITSAlgorithmUtils.getHashAlgorithm(signer.getDigestAlgorithm().getAlgorithm()))
            .setTbsData(toBeSignedData)
            .setSigner(SignerIdentifier.builder().digest(identifier).build())
            .setSignature(signer.getSignature()).build());
    }


    private static void write(OutputStream os, byte[] data)
    {
        try
        {
            os.write(data);
            os.flush();
            os.close();
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

}
