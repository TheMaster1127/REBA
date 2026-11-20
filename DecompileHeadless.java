// DecompileHeadless.java
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class DecompileHeadless extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) return;

        String target = args[0];
        Function targetFunc = null;
        Address directAddr = null;

        try {
            long rawOffset = Long.parseUnsignedLong(target.replace("0x", ""), 16);
            directAddr = toAddr(rawOffset);
            targetFunc = getFunctionAt(directAddr);
            if (targetFunc == null) {
                Address pieAddr = currentProgram.getImageBase().add(rawOffset);
                targetFunc = getFunctionAt(pieAddr);
                if (targetFunc == null) targetFunc = getFunctionContaining(pieAddr);
            }
        } catch (Exception e) {}

        if (targetFunc == null) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(target) || f.getName().contains(target)) {
                    targetFunc = f;
                    break;
                }
            }
        }

        if (targetFunc == null && directAddr != null) {
            try {
                disassemble(directAddr);
                targetFunc = createFunction(directAddr, "entry_point");
            } catch (Exception e) {}
        }

        System.out.println("=== GHIDRA_C_START ===");
        if (targetFunc != null) {
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            DecompileResults res = decomp.decompileFunction(targetFunc, 60, monitor);

            if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
                System.out.println("// Signature: " + targetFunc.getPrototypeString(true, true));
                System.out.println("// Calling Convention: " + targetFunc.getCallingConventionName());
                if (targetFunc.isThunk()) System.out.println("// Thunk to: " + targetFunc.getThunkedFunction(true).getName());
                System.out.println(res.getDecompiledFunction().getC());
            } else {
                System.out.println("// Decompiler error: " + res.getErrorMessage());
            }
        } else {
            System.out.println("// Error: Function '" + target + "' not found in Ghidra.");
        }
        System.out.println("=== GHIDRA_C_END ===");
        System.out.flush();
    }
}
