package org.bouncycastle.dvcs;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.dvcs.Data;
import org.bouncycastle.asn1.dvcs.ServiceType;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;

/**
 * Data piece of DVCRequest object (DVCS Data structure).
 * Its contents depend on the service type.
 * Its subclasses define the service-specific interface.
 * <p/>
 * The concrete objects of DVCRequestData are created by buildDVCRequestData static method.
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
     * @param data
     */
    protected DVCSRequestData(Data data)
    {
        this.data = data;
    }

    /**
     * Convert to ASN.1 structure (Data).
     *
     * @return
     */
    public Data toASN1Structure()
    {
        return data;
    }
}
