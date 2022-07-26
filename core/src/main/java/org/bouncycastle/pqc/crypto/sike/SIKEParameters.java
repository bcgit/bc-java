package org.bouncycastle.pqc.crypto.sike;

public class SIKEParameters
{
    public static final SIKEParameters sikep434 = new SIKEParameters(434, false,"sikep434");
    public static final SIKEParameters sikep503 = new SIKEParameters(503, false,"sikep503");
    public static final SIKEParameters sikep610 = new SIKEParameters(610, false,"sikep610");
    public static final SIKEParameters sikep751 = new SIKEParameters(751, false,"sikep751");

    public static final SIKEParameters sikep434_compressed = new SIKEParameters(434, true,"sikep434_compressed");
    public static final SIKEParameters sikep503_compressed = new SIKEParameters(503, true,"sikep503_compressed");
    public static final SIKEParameters sikep610_compressed = new SIKEParameters(610, true,"sikep610_compressed");
    public static final SIKEParameters sikep751_compressed = new SIKEParameters(751, true,"sikep751_compressed");

    private final String name;
    private final SIKEEngine engine;

    private SIKEParameters(int ver, boolean isCompressed, String name)
    {
        this.name = name;
        this.engine = new SIKEEngine(ver, isCompressed);
    }

    SIKEEngine getEngine()
    {
        return engine;
    }

    public String getName()
    {
        return name;
    }

    public int getSessionKeySize()
    {
        return engine.getDefaultSessionKeySize();
    }
}
