package org.bouncycastle.pqc.crypto.sike;

import javax.naming.OperationNotSupportedException;

public class SIKEParameters
{
    private static class SikeP434Engine
    {
        protected static final SIKEEngine Instance = new SIKEEngine(434, false);
    }

    private static class SikeP503Engine
    {
        protected static final SIKEEngine Instance = new SIKEEngine(503, false);
    }

    private static class SikeP610Engine
    {
        protected static final SIKEEngine Instance = new SIKEEngine(610, false);
    }

    private static class SikeP751Engine
    {
        protected static final SIKEEngine Instance = new SIKEEngine(751, false);
    }

    private static class SikeP434CompressedEngine
    {
        protected static final SIKEEngine Instance = new SIKEEngine(434, true);
    }

    private static class SikeP503CompressedEngine
    {
        protected static final SIKEEngine Instance = new SIKEEngine(503, true);
    }

    private static class SikeP610CompressedEngine
    {
        protected static final SIKEEngine Instance = new SIKEEngine(610, true);
    }

    private static class SikeP751CompressedEngine
    {
        protected static final SIKEEngine Instance = new SIKEEngine(751, true);
    }

    public static final SIKEParameters sikep434 = new SIKEParameters(434, false,"sikep434");
    public static final SIKEParameters sikep503 = new SIKEParameters(503, false,"sikep503");
    public static final SIKEParameters sikep610 = new SIKEParameters(610, false,"sikep610");
    public static final SIKEParameters sikep751 = new SIKEParameters(751, false,"sikep751");

    public static final SIKEParameters sikep434_compressed = new SIKEParameters(434, true,"sikep434_compressed");
    public static final SIKEParameters sikep503_compressed = new SIKEParameters(503, true,"sikep503_compressed");
    public static final SIKEParameters sikep610_compressed = new SIKEParameters(610, true,"sikep610_compressed");
    public static final SIKEParameters sikep751_compressed = new SIKEParameters(751, true,"sikep751_compressed");

    private final String name;
    private final int ver;
    private final boolean isCompressed;
    private SIKEParameters(int ver, boolean isCompressed, String name)
    {
        this.name = name;
        this.ver = ver;
        this.isCompressed = isCompressed;
    }

    SIKEEngine getEngine()
    {
        if (isCompressed)
        {
            switch (ver)
            {
                case 434:   return SikeP434CompressedEngine.Instance;
                case 503:   return SikeP503CompressedEngine.Instance;
                case 610:   return SikeP610CompressedEngine.Instance;
                case 751:   return SikeP751CompressedEngine.Instance;
                default:   return null;
            }
        }
        else
        {
            switch (ver)
            {
                case 434:   return SikeP434Engine.Instance;
                case 503:   return SikeP503Engine.Instance;
                case 610:   return SikeP610Engine.Instance;
                case 751:   return SikeP751Engine.Instance;
                default:    return null;
            }
        }
    }

    public String getName()
    {
        return name;
    }

    public int getSessionKeySize()
    {
        return getEngine().getDefaultSessionKeySize();
    }
}
