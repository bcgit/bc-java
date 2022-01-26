package org.bouncycastle.oer.its.ieee1609dot2;

/**
 * <pre>
 *     RecipientInfo ::= CHOICE {
 *         pskRecipInfo PreSharedKeyReicpientInfo,
 *         symmRecipInfo SymmRecipientInfo,
 *         certRecipInfo PKRecipientInfo,
 *         signedDataRecipInfo PKRecipientInfo,
 *         rekRecipInfo PKRecipientInfo
 *     }
 * </pre>
 */
public class RecipientInfo
{


    public static RecipientInfo getInstance(Object object)
    {
        return new RecipientInfo();
    }
}
