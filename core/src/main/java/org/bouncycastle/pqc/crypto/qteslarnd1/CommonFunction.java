package org.bouncycastle.pqc.crypto.qteslarnd1;

class CommonFunction
{

    /****************************************************************************************************
     * Description:	Checks Whether the Two Parts of Arrays are Equal to Each Other
     *
     * @param        left            Left Array
     * @param        leftOffset        Starting Point of the Left Array
     * @param        right            Right Array
     * @param        rightOffset        Starting Point of the Right Array
     * @param        length            Length to be Compared from the Starting Point
     *
     * @return true            Equal
     *				false			Different
     ****************************************************************************************************/
    public static boolean memoryEqual(byte[] left, int leftOffset, byte[] right, int rightOffset, int length)
    {

        if ((leftOffset + length <= left.length) && (rightOffset + length <= right.length))
        {

            for (int i = 0; i < length; i++)
            {

                if (left[leftOffset + i] != right[rightOffset + i])
                {

                    return false;

                }

            }

            return true;

        }
        else
        {

            return false;

        }

    }

    /****************************************************************************
     * Description:	Converts 2 Consecutive Bytes in "load" to A Number of "Short"
     *				from A Known Position
     *
     * @param        load            Source Array
     * @param        loadOffset        Starting Position
     *
     * @return A Number of "Short"
     ****************************************************************************/
    public static short load16(final byte[] load, int loadOffset)
    {

        short number = 0;

        if (load.length - loadOffset >= Const.SHORT_SIZE / Const.BYTE_SIZE)
        {

            for (int i = 0; i < Const.SHORT_SIZE / Const.BYTE_SIZE; i++)
            {

                number ^= (short)(load[loadOffset + i] & 0xFF) << (Const.BYTE_SIZE * i);

            }

        }
        else
        {

            for (int i = 0; i < load.length - loadOffset; i++)
            {

                number ^= (short)(load[loadOffset + i] & 0xFF) << (Const.BYTE_SIZE * i);

            }

        }

        return number;

    }

    /******************************************************************************
     * Description:	Converts 4 Consecutive Bytes in "load" to A Number of "Integer"
     *				from A Known Position
     *
     * @param        load            Source Array
     * @param        loadOffset        Starting Position
     *
     * @return A Number of "Integer"
     ******************************************************************************/
    public static int load32(final byte[] load, int loadOffset)
    {

        int number = 0;

        if (load.length - loadOffset >= Const.INT_SIZE / Const.BYTE_SIZE)
        {

            for (int i = 0; i < Const.INT_SIZE / Const.BYTE_SIZE; i++)
            {

                number ^= (int)(load[loadOffset + i] & 0xFF) << (Const.BYTE_SIZE * i);

            }

        }
        else
        {


            for (int i = 0; i < load.length - loadOffset; i++)
            {

                number ^= (int)(load[loadOffset + i] & 0xFF) << (Const.BYTE_SIZE * i);

            }

        }

        return number;

    }

    /***************************************************************************
     * Description:	Converts 8 Consecutive Bytes in "load" to A Number of "Long"
     *				from A Known Position
     *
     * @param        load            Source Array
     * @param        loadOffset        Starting Position
     *
     * @return A Number of "Long"
     ***************************************************************************/
    public static long load64(final byte[] load, int loadOffset)
    {

        long number = 0L;

        if (load.length - loadOffset >= Const.LONG_SIZE / Const.BYTE_SIZE)
        {

            for (int i = 0; i < Const.LONG_SIZE / Const.BYTE_SIZE; i++)
            {

                number ^= (long)(load[loadOffset + i] & 0xFF) << (Const.BYTE_SIZE * i);

            }

        }
        else
        {

            for (int i = 0; i < load.length - loadOffset; i++)
            {

                number ^= (long)(load[loadOffset + i] & 0xFF) << (Const.BYTE_SIZE * i);

            }

        }

        return number;

    }

    /*****************************************************************************
     * Description:	Converts A Number of "Short" to 2 Consecutive Bytes in "store"
     *				from a known position
     *
     * @param        store            Destination Array
     * @param        storeOffset        Starting position
     * @param        number            Source Number
     *
     * @return none
     *****************************************************************************/
    public static void store16(byte[] store, int storeOffset, short number)
    {

        if (store.length - storeOffset >= Const.SHORT_SIZE / Const.BYTE_SIZE)
        {

            for (int i = 0; i < Const.SHORT_SIZE / Const.BYTE_SIZE; i++)
            {

                store[storeOffset + i] = (byte)((number >> (Const.BYTE_SIZE * i)) & 0xFF);

            }

        }
        else
        {

            for (int i = 0; i < store.length - storeOffset; i++)
            {

                store[storeOffset + i] = (byte)((number >> (Const.BYTE_SIZE * i)) & 0xFF);

            }

        }

    }

    /*******************************************************************************
     * Description:	Converts A Number of "Integer" to 4 Consecutive Bytes in "store"
     * 				from A Known Position
     *
     * @param        store            Destination Array
     * @param        storeOffset        Starting Position
     * @param        number:			Source Number
     *
     * @return none
     *******************************************************************************/
    public static void store32(byte[] store, int storeOffset, int number)
    {

        if (store.length - storeOffset >= Const.INT_SIZE / Const.BYTE_SIZE)
        {

            for (int i = 0; i < Const.INT_SIZE / Const.BYTE_SIZE; i++)
            {

                store[storeOffset + i] = (byte)((number >> (Const.BYTE_SIZE * i)) & 0xFF);

            }

        }
        else
        {

            for (int i = 0; i < store.length - storeOffset; i++)
            {

                store[storeOffset + i] = (byte)((number >> (Const.BYTE_SIZE * i)) & 0xFF);

            }

        }

    }

    /****************************************************************************
     * Description:	Converts A Number of "Long" to 8 Consecutive Bytes in "store"
     * 				from A Known Position
     *
     * @param        store            Destination Array
     * @param        storeOffset        Starting Position
     * @param        number            Source Number
     *
     * @return none
     ****************************************************************************/
    public static void store64(byte[] store, int storeOffset, long number)
    {

        if (store.length - storeOffset >= Const.LONG_SIZE / Const.BYTE_SIZE)
        {

            for (int i = 0; i < Const.LONG_SIZE / Const.BYTE_SIZE; i++)
            {

                store[storeOffset + i] = (byte)((number >> (Const.BYTE_SIZE * i)) & 0xFFL);

            }

        }
        else
        {

            for (int i = 0; i < store.length - storeOffset; i++)
            {

                store[storeOffset + i] = (byte)((number >> (Const.BYTE_SIZE * i)) & 0xFFL);

            }

        }

    }

}