import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;

public class TxHandler {
    private UTXOPool pool;

    /**
     * Creates a public ledger whose current UTXOPool (collection