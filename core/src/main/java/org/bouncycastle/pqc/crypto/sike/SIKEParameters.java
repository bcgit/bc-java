package org.bouncycastle.pqc.crypto.sike;

public class SIKEParameters
{

    public static final SIKEParameters sikep434 = new SIKEParameters(434, "sikep434");
    public static final SIKEParameters sikep503 = new SIKEParameters(503, "sikep503");
    public static final SIKEParameters sikep610 = new SIKEParameters(610, "sikep610");
    public static final SIKEParameters sikep751 = new SIKEParameters(751, "sikep751");
//    public static final SIKEParameters sikep503();
//    public static final SIKEParameters sikep610();
//    public static final SIKEParameters sikep751();

    private final String name;
    private final SIKEEngine engine;

    public SIKEParameters(int ver, String name)
    {
        this.name = name;
        this.engine = new SIKEEngine(ver, null);
    }

    public SIKEEngine getEngine()
    {
        return engine;
    }


}
