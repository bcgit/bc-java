package org.bouncycastle.cms;

import java.util.Map;

import org.bouncycastle.asn1.cms.AttributeTable;

/**
 * Note: The SIGNATURE parameter is only available when generating unsigned attributes.
 */
public interface CMSAttributeTableGenerator
{
    String CONTENT_TYPE = "contentType";
    String DIGEST = "digest";
    String SIGNATURE = "encryptedDigest";
    String DIGEST_ALGORITHM_IDENTIFIER = "digestAlgID";
    String MAC_ALGORITHM_IDENTIFIER = "macAlgID";
    String SIGNATURE_ALGORITHM_IDENTIFIER = "signatureAlgID";

    AttributeTable getAttributes(Map parameters)
        throws CMSAttributeTableGenerationException;
}
