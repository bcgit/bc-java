package org.bouncycastle.its;

import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.its.operator.ETSIDataSigner;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.its.ieee1609dot2.Certificate;
import org.bouncycastle.oer.its.ieee1609dot2.HashedData;
import org.bouncycastle.oer.its.ieee1609dot2.HeaderInfo;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Data;
import org.bouncycastle.oer.its.ieee1609dot2.SequenceOfCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.SignedData;
import org.bouncycastle.oer.its.ieee1609dot2.SignedDataPayload;
import org.bouncycastle.oer.its.ieee1609dot2.SignerIdentifier;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedData;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;

public class ETSISignedDataBuilder
{

    private static final Element def = IEEE1609dot2.ToBeSignedData.build();

    private Ieee1609Dot2Data data;
    private HashedData extDataHash;
    private HeaderInfo headerInfo;


    public ETSISignedDataBuilder()
    {

    }

    public static ETSISignedDataBuilder builder()
    {
        return new ETSISignedDataBuilder();
    }

    public ETSISignedDataBuilder setData(Ieee1609Dot2Data data)
    {
        this.data = data;
        return this;
    }

    public ETSISignedDataBuilder setExtDataHash(HashedData extDataHash)
    {
        this.extDataHash = extDataHash;
        return this;
    }

    public ETSISignedDataBuilder setHeaderInfo(HeaderInfo headerInfo)
    {
        this.headerInfo = headerInfo;
        return this;
    }


    private ToBeSignedData getToBeSignedData()
    {

        SignedDataPayload signedDataPayload = new SignedDataPayload(data, extDataHash);

        return ToBeSignedData.builder()
            .setPayload(signedDataPayload)
            .setHeaderInfo(headerInfo)
            .createToBeSignedData();
    }


    /**
     * Self signed
     *
     * @param signer
     * @return
     */
    public ETSISignedData build(ETSIDataSigner signer)
    {
        ToBeSignedData toBeSignedData = getToBeSignedData();
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
        ToBeSignedData toBeSignedData = getToBeSignedData();
        write(signer.getOutputStream(), OEREncoder.toByteArray(toBeSignedData, def));

        List<Certificate> certificates = new ArrayList<Certificate>();
        for (ITSCertificate certificate : certificateList)
        {
            certificates.add(Certificate.getInstance(certificate.toASN1Structure()));
        }

        return new ETSISignedData(SignedData.builder()
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

        ToBeSignedData toBeSignedData = getToBeSignedData();
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
