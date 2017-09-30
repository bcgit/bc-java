package com.github.gv2011.asn1;


/**
 * Interface implemented by objects that can be converted from streaming to in-memory objects.
 */
public interface InMemoryRepresentable
{
    /**
     * Get the in-memory representation of the ASN.1 object.
     * @return an ASN1Primitive representing the loaded object.
     * @throws IOException for bad input data.
     */
    ASN1Primitive getLoadedObject();
}
