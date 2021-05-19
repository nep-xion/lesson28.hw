
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

public class UTXOPool {

    /**
     * The current collection of UTXOs, with each one mapped to its corresponding transaction output
     */
    private HashMap<UTXO, Transaction.Output> H;

    /** Creates a new empty UTXOPool */
    public UTXOPool() {
        H = new HashMap<UTXO, Transaction.Output>();
    }
