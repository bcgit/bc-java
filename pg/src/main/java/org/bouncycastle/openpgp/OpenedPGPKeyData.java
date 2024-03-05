package org.bouncycastle.openpgp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.gpg.SExpression;
import org.bouncycastle.gpg.SExprParser;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;

/**
 * Wraps PGP key headers and pgp key SExpression
 */
public class OpenedPGPKeyData
{
    private final List<PGPExtendedKeyHeader> headerList;
    private final SExpression keyExpression;

    public OpenedPGPKeyData(List<PGPExtendedKeyHeader> headerList, SExpression keyExpression)
    {
        this.headerList = Collections.unmodifiableList(headerList);
        this.keyExpression = keyExpression;
    }

    public List<PGPExtendedKeyHeader> getHeaderList()
    {
        return headerList;
    }

    public SExpression getKeyExpression()
    {
        return keyExpression;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public String getKeyType()
    {
        return null;
    }

    public ExtendedPGPSecretKey getKeyData(PGPPublicKey publicKey, PGPDigestCalculatorProvider digestCalculatorProvider,
                                           PBEProtectionRemoverFactory keyProtectionRemoverFactory,
                                           KeyFingerPrintCalculator fingerPrintCalculator, int maxDepth)
        throws PGPException, IOException
    {
        int type = SExprParser.getProtectionType(keyExpression.getString(0));
        ArrayList<PGPExtendedKeyAttribute> attributeList = new ArrayList<PGPExtendedKeyAttribute>();
        if (type == SExprParser.ProtectionFormatTypeTags.PRIVATE_KEY || type == SExprParser.ProtectionFormatTypeTags.PROTECTED_PRIVATE_KEY ||
            type == SExprParser.ProtectionFormatTypeTags.SHADOWED_PRIVATE_KEY)
        {
            SExpression expression = getKeyExpression().getExpression(1);
            String keyType = expression.getString(0);
            PublicKeyAlgorithmTags[] secretKey = SExprParser.getPGPSecretKey(keyProtectionRemoverFactory, fingerPrintCalculator, publicKey, maxDepth, type, expression,
                keyType, digestCalculatorProvider);
            if (keyType.equals("rsa"))
            {
                for (Iterator it = expression.filterOut(new String[]{"rsa", "e", "n", "d", "p", "q", "u", "protected"}).getValues().iterator(); it.hasNext(); )
                {
                    Object o = it.next();
                    if (o instanceof SExpression)
                    {
                        attributeList.add(((SExpression)o).toAttribute());
                    }
                    else
                    {
                        attributeList.add(PGPExtendedKeyAttribute.builder().addAttribute(o).build());
                    }
                }
            }
            return new ExtendedPGPSecretKey(headerList, attributeList, (SecretKeyPacket)secretKey[0], (PGPPublicKey)secretKey[1]);
        }
        return null;
    }

    public static class Builder
    {
        private List<PGPExtendedKeyHeader> headerList = new ArrayList<PGPExtendedKeyHeader>();
        private SExpression keyExpression;

        public Builder setHeaderList(List<PGPExtendedKeyHeader> headerList)
        {
            this.headerList = headerList;
            return this;
        }

        public Builder setKeyExpression(SExpression keyExpression)
        {
            this.keyExpression = keyExpression;
            return this;
        }

        public OpenedPGPKeyData build()
        {
            return new OpenedPGPKeyData(headerList, keyExpression);
        }

        public void add(PGPExtendedKeyHeader pgpExtendedKeyHeader)
        {
            headerList.add(pgpExtendedKeyHeader);
        }
    }

}
