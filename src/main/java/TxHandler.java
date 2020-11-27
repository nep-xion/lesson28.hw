import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;

public class TxHandler {
    private UTXOPool pool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        pool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        // Check if all outputs claimed by {@code tx} are in the current UTXO pool
        for (int i = 0; i < tx.numInputs(); ++i) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            if (!pool.contains(utxo)) {
                return false;
            }
        }

        // Check if the signatures on each input of {@code tx} are valid
        for (int i = 0; i < tx.numInputs(); ++i) {
            byte[] data = tx.getRawDataToSign(i);
            Transaction.Input in = tx.getInput(i);
            if (in.signature == null) {
                return false;
            }
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            Transaction.Output out = pool.getTxOutput(utxo);
            if (!Crypto.verifySignature(out.address, data, in.signature)) {
                return false;
            }
        }

        // No UTXO is claimed multiple times by {@code tx}
        Set<Integer> hashCodes = new HashSet<Integer>();
        for (int i = 0; i < tx.numInputs(); ++i) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            if (hashCodes.contains(utxo.hashCode())) {
                return false;
            }
            hashCodes.add(utxo.hashCode());
        }

        // All of {@code tx}s output values are non-negative
        for (int i = 0; i < tx.numOutputs(); i++) {
            Transaction.Output out = tx.getOutput(i);
            if (out.value < 0) {
                return false;
            }
        }

        // the sum of {@code tx}s input values is greater than or equal to the
        // sum of its output values; and false otherwise.
        double outputSum = 0;
        double inputSum = 0;
        for (int i = 0; i < tx.numOutputs(); ++i) {
            Transaction.Output out = tx.getOutput(i);
            outputSum += out.value;
        }
        for (int i = 0; i < tx.numInputs(); ++i) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTX