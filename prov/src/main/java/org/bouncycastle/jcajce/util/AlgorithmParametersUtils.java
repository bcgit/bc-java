package org.bouncycastle.jcajce.util;

import java.io.IOException;
import java.security.AlgorithmParameters;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * General JCA/JCE utility methods.
 */
public class AlgorithmParametersUtils
{


    private AlgorithmParametersUtils()
    {

    }

    /**
     * Extract an ASN.1 encodable from an AlgorithmParameters object.
     *
     * @param params the object to get the encoding used to create the return value.
     * @return an ASN.1 object representing the primitives making up the params parameter.
     * @throws IOException if an encoding cannot be extracted.
     */
    public static ASN1Encodable extractParameters(AlgorithmParameters params)
        throws IOException
    {
        // we try ASN.1 explicitly first just in case and then role back to the default.
        ASN1Encodable asn1Params;
        try
        {
            asn1Params = ASN1Primitive.fromByteArray(params.getEncoded("ASN.1"));
        }
        catch (Exception ex)
        {
            asn1Params = ASN1Primitive.fromByteArray(params.getEncoded());
        }

        return asn1Params;
    }

    /**
     * Load an AlgorithmParameters object with the passed in ASN.1 encodable - if possible.
     *
     * @param params the AlgorithmParameters object to be initialised.
     * @param sParams the ASN.1 encodable to initialise params with.
     * @throws IOException if the parameters cannot be initialised.
     */
    public static void loadParameters(AlgorithmParameters params, ASN1Encodable sParams)
        throws IOException
    {
        // we try ASN.1 explicitly first just in case and then role back to the default.
        try
        {
            params.init(sParams.toASN1Primitive().getEncoded(), "ASN.1");
        }
        catch (Exception ex)
        {
            params.init(sParams.toASN1Primitive().getEncoded());
        }
    }
}
