import ghidra.app.script.GhidraScript;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;

public class ExportCFG extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outDir = System.getenv("CFG_OUT_DIR");
        if (outDir == null) outDir = "/tmp/cfg_out";
        new File(outDir).mkdirs();

        BasicBlockModel model = new BasicBlockModel(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();

        for (Function f : fm.getFunctions(true)) {
            if (f.isThunk() || f.isExternal()) continue;

            CodeBlockIterator blocks = model.getCodeBlocksContaining(f.getBody(), monitor);
            List<CodeBlock> blockList = new ArrayList<>();
            Map<CodeBlock, Integer> blockIndex = new HashMap<>();
            while (blocks.hasNext()) {
                CodeBlock b = blocks.next();
                blockIndex.put(b, blockList.size());
                blockList.add(b);
            }

            StringBuilder sb = new StringBuilder();
            sb.append("{\n  \"function\": \"").append(f.getName()).append("\",\n");
            sb.append("  \"entry\": \"").append(f.getEntryPoint()).append("\",\n");
            sb.append("  \"blocks\": [\n");

            for (int i = 0; i < blockList.size(); i++) {
                CodeBlock b = blockList.get(i);
                int instrCount = 0;
                InstructionIterator ii = currentProgram.getListing().getInstructions(b, true);
                while (ii.hasNext()) { ii.next(); instrCount++; }
                sb.append("    {\"id\": ").append(i)
                  .append(", \"start\": \"").append(b.getFirstStartAddress()).append("\"")
                  .append(", \"end\": \"").append(b.getMaxAddress()).append("\"")
                  .append(", \"instrs\": ").append(instrCount).append("}");
                if (i < blockList.size() - 1) sb.append(",");
                sb.append("\n");
            }

            sb.append("  ],\n  \"edges\": [\n");

            boolean firstEdge = true;
            for (int i = 0; i < blockList.size(); i++) {
                CodeBlock b = blockList.get(i);
                CodeBlockReferenceIterator dests = b.getDestinations(monitor);
                while (dests.hasNext()) {
                    CodeBlockReference ref = dests.next();
                    CodeBlock dest = ref.getDestinationBlock();
                    if (!blockIndex.containsKey(dest)) continue;
                    if (!firstEdge) sb.append(",\n");
                    sb.append("    {\"from\": ").append(i)
                      .append(", \"to\": ").append(blockIndex.get(dest))
                      .append(", \"type\": \"").append(ref.getFlowType().toString()).append("\"}");
                    firstEdge = false;
                }
            }

            sb.append("\n  ]\n}\n");

            String safeName = f.getName().replaceAll("[^a-zA-Z0-9_]", "_");
            File out = new File(outDir, safeName + "_" + f.getEntryPoint() + ".json");
            try (FileWriter fw = new FileWriter(out)) {
                fw.write(sb.toString());
            }
            println("exported: " + out.getName() + " (" + blockList.size() + " blocks)");
        }
    }
}
