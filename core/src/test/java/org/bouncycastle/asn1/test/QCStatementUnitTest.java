package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.QcType;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
import org.bouncycastle.util.test.SimpleTest;

public class QCStatementUnitTest 
    extends SimpleTest
{
    public String getName()
    {
        return "QCStatement";
    }

    public void performTest() 
        throws Exception
    {
        QCStatement mv = new QCStatement(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1);

        checkConstruction(mv, RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1, null);
        
        ASN1Encodable info = new SemanticsInformation(new ASN1ObjectIdentifier("1.2"));
        
        mv = new QCStatement(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1, info);

        checkConstruction(mv, RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1, info);
        
        mv = QCStatement.getInstance(null);
        
        if (mv != null)
        {
            fail("null getInstance() failed.");
        }
        
        try
        {
            QCStatement.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        // ETSI EN 319 412-5 qualified-certificate statements (github #1467).

        // QcCompliance and QcSSCD are info-less flags.
        checkConstruction(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance),
            ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance, null);
        checkConstruction(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD),
            ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD, null);

        // QcType: statementInfo is the named QcType (SEQUENCE OF OBJECT IDENTIFIER).
        QcType qcTypeInfo = new QcType(new ASN1ObjectIdentifier[]{
            ETSIQCObjectIdentifiers.id_etsi_qct_esign,
            ETSIQCObjectIdentifiers.id_etsi_qct_eseal,
            ETSIQCObjectIdentifiers.id_etsi_qct_web
        });

        checkConstruction(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType, qcTypeInfo),
            ETSIQCObjectIdentifiers.id_etsi_qcs_QcType, qcTypeInfo);

        // QcCClegislation: statementInfo is SEQUENCE OF PrintableString (ISO 3166-1 alpha-2).
        ASN1EncodableVector ccCodes = new ASN1EncodableVector();
        ccCodes.add(new DERPrintableString("DE"));
        ccCodes.add(new DERPrintableString("CH"));
        DERSequence ccInfo = new DERSequence(ccCodes);

        checkConstruction(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCClegislation, ccInfo),
            ETSIQCObjectIdentifiers.id_etsi_qcs_QcCClegislation, ccInfo);

        // RetentionPeriod: statementInfo is INTEGER (years).
        ASN1Integer retention = new ASN1Integer(BigInteger.valueOf(10));

        checkConstruction(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_RetentionPeriod, retention),
            ETSIQCObjectIdentifiers.id_etsi_qcs_RetentionPeriod, retention);

        // LimitValue: statementInfo is MonetaryValue.
        MonetaryValue limit = new MonetaryValue(new Iso4217CurrencyCode("EUR"), 1000, 2);

        checkConstruction(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue, limit),
            ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue, limit);
    }

    private void checkConstruction(
         QCStatement mv,
         ASN1ObjectIdentifier statementId,
         ASN1Encodable statementInfo) 
         throws IOException
    {
        checkStatement(mv, statementId, statementInfo);
        
        mv = QCStatement.getInstance(mv);
        
        checkStatement(mv, statementId, statementInfo);
        
        ASN1InputStream aIn = new ASN1InputStream(mv.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
        
        mv = QCStatement.getInstance(seq);
        
        checkStatement(mv, statementId, statementInfo);
    }

    private void checkStatement(
        QCStatement         qcs,
        ASN1ObjectIdentifier statementId,
        ASN1Encodable       statementInfo)
        throws IOException
    {
        if (!qcs.getStatementId().equals(statementId))
        {
            fail("statementIds don't match.");
        }
        
        if (statementInfo != null)
        {
            if (!qcs.getStatementInfo().equals(statementInfo))
            {
                fail("statementInfos don't match.");
            }
        }
        else if (qcs.getStatementInfo() != null)
        {
            fail("statementInfo found when none expected.");
        }
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new QCStatementUnitTest());
    }
}
