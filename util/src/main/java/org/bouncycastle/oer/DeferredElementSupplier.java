package org.bouncycastle.oer;

public class DeferredElementSupplier
    implements ElementSupplier
{

    private final OERDefinition.Builder src;
    private Element buildProduct;

    public DeferredElementSupplier(OERDefinition.Builder src)
    {
        this.src = src;
    }


    public Element build()
    {
        synchronized (this)
        {
            if (buildProduct == null)
            {
                buildProduct = src.build();
            }
            return buildProduct;
        }
    }
}
