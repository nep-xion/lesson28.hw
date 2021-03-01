import java.util.Arrays;

public class UTXO implements Comparable<UTXO> {

    /** Hash of the transaction from which this UTXO originates */
    private byte[] txHash;

    /** Index of the corresponding output in said transaction */
    private