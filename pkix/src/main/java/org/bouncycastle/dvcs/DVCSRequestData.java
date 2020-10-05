package org.bouncycastle.dvcs;

import org.bouncycastle.asn1.dvcs.Data;

/**
 * Data piece of DVCRequest object (DVCS Data structure).
 * Its contents depend on the service type.
 * Its subclasses define the service-specific interface.
 * <p>
 * The concrete objects of DVCRequestData are created by buildDVCRequestData static method.
 * </p>
 */
public abstract class DVCSRequestData
{
    /**
     * The underlying data object is accessible by subclasses.
     */
    protected Data data;

    /**
     * The constructor is accessible by subclasses.
     *
     * @param data the data piece for this request.
     */
    protected DVCSRequestData(Data data)
    {
        this.data = data;
    }

    /**
     * Convert to ASN.1 structure (Data).
     *
     * @return a Data object.
     */
    public Data toASN1Structure()
    {
        return data;
    }
}
