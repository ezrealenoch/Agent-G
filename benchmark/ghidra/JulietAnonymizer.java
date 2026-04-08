/*
 * JulietAnonymizer - Strip Juliet-test-suite-specific identifiers
 *
 * Runs as a Ghidra preScript before OGhidraHeadlessServer to rename all
 * function symbols matching Juliet patterns (CWE*, *_bad, *_good, printLine,
 * etc.) to generic FUN_<address> names. This prevents an LLM from cheating
 * the vulnerability classification by reading the function name.
 *
 * Usage:
 *   analyzeHeadless <project> <name> -import <binary> \
 *     -preScript JulietAnonymizer.java \
 *     -postScript OGhidraHeadlessServer.java <port>
 *
 * The anonymizer:
 *   1. Iterates all functions
 *   2. For each function whose name matches a Juliet leak pattern:
 *      a. Renames it to FUN_<hex_address> with SourceType.USER_DEFINED
 *         (so auto-analysis cannot override it)
 *      b. Clears plate, repeatable, and listing comments
 *   3. Whitelists standard runtime entry points (main, _start, etc.)
 *   4. Saves a side mapping file for later de-anonymization (optional)
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class JulietAnonymizer extends GhidraScript {

    // Names that must NEVER be renamed (standard runtime entry points)
    private static final Set<String> WHITELIST = new HashSet<>(Arrays.asList(
        "main", "_start", "entry", "__DT_INIT", "_init", "_fini",
        "__libc_csu_init", "__libc_csu_fini", "__libc_start_main",
        "DllMain", "WinMain", "wWinMain", "ServiceMain",
        "_DllMainCRTStartup", "__tmainCRTStartup", "___tmainCRTStartup",
        "__do_global_dtors_aux", "frame_dummy", "deregister_tm_clones",
        "register_tm_clones", "__do_global_ctors_aux", "_dl_relocate_static_pie",
        "__cxa_finalize", "abort", "exit", "_exit"
    ));

    // Pattern matching Juliet test suite leaks (case-insensitive)
    private static final Pattern LEAK_PATTERN = Pattern.compile(
        "(?i)(" +
            "CWE\\d+|" +                                  // CWE121, CWE-121, etc.
            "_bad\\d*$|" +                                // foo_bad, foo_bad5
            "_good\\d*$|" +                               // foo_good, foo_good3
            "^bad\\d*$|" +                                // bad, bad5
            "^good\\d*$|" +                               // good, good1
            "stack[_-]based|" +
            "heap[_-]based|" +
            "buffer[_-]over|" +
            "buffer[_-]under|" +
            "use[_-]after[_-]free|" +
            "double[_-]free|" +
            "null[_-]deref|" +
            "format[_-]string|" +
            "integer[_-]over|" +
            "integer[_-]under|" +
            "divide[_-]by[_-]zero|" +
            "memory[_-]leak|" +
            "globalReturns|" +
            "globalArgv|globalArgc|globalFalse|globalTrue|" +
            "print[A-Za-z]*Line|" +                       // any printXxxLine helper
            "decodeHex[A-Za-z]*|" +                       // decodeHexChars, decodeHexWChars
            "good[GB]\\d?[GB]?|" +                        // goodG2B, goodB2G, goodG, etc.
            "staticReturns|" +
            "static_returns|" +
            "Stack_Based|Heap_Based|Buffer_Overflow|" +
            "Process_Control|Integer_Overflow|" +
            "Memory_Leak|Double_Free|Use_After_Free" +
        ")"
    );

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            printerr("[JulietAnonymizer] No program loaded");
            return;
        }

        println("[JulietAnonymizer] Starting anonymization of " + currentProgram.getName());

        List<String[]> mapping = new ArrayList<>();
        int renamedFunctions = 0;
        int clearedComments = 0;
        int skippedWhitelisted = 0;

        int tx = currentProgram.startTransaction("JulietAnonymizer");
        try {
            int renamedDataSymbols = 0;

            // ── Phase 1: Iterate ALL symbols (not just functions) ──
            // This is critical because non-stripped ELF binaries with debug
            // info have MULTIPLE symbols at the same address — both a primary
            // function symbol AND duplicate "label" symbols from DWARF.
            // Renaming via Function.setName() only renames the primary;
            // we need to rename every leaky symbol regardless of type.
            SymbolTable symTable = currentProgram.getSymbolTable();

            // Snapshot symbols first because we'll be mutating them
            List<Symbol> allSymbols = new ArrayList<>();
            SymbolIterator symIter = symTable.getAllSymbols(true);
            while (symIter.hasNext()) {
                allSymbols.add(symIter.next());
            }

            for (Symbol sym : allSymbols) {
                String name = sym.getName();

                if (WHITELIST.contains(name)) {
                    skippedWhitelisted++;
                    continue;
                }
                // Already renamed (idempotent)
                if (name.startsWith("FUN_") || name.startsWith("DAT_") ||
                    name.startsWith("LAB_")) {
                    continue;
                }

                if (!LEAK_PATTERN.matcher(name).find()) {
                    continue;
                }

                Address addr = sym.getAddress();
                if (addr == null) continue;

                // Choose prefix based on symbol type
                String prefix;
                String typeStr = sym.getSymbolType().toString();
                if ("Function".equals(typeStr)) {
                    prefix = "FUN_";
                } else if ("Label".equals(typeStr)) {
                    prefix = "LAB_";
                } else {
                    prefix = "DAT_";
                }
                String newName = prefix + addr.toString();

                try {
                    sym.setName(newName, SourceType.USER_DEFINED);
                    mapping.add(new String[] { addr.toString(), name, newName });
                    if ("Function".equals(typeStr)) {
                        renamedFunctions++;
                    } else {
                        renamedDataSymbols++;
                    }
                } catch (Exception e) {
                    // Some symbols can't be renamed (external refs, etc.) — skip silently
                }
            }

            // ── Phase 2: Clear function comments ──
            for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
                try {
                    if (func.getComment() != null) {
                        func.setComment(null);
                        clearedComments++;
                    }
                    if (func.getRepeatableComment() != null) {
                        func.setRepeatableComment(null);
                        clearedComments++;
                    }
                } catch (Exception e) {
                    // Ignore comment clear failures
                }
            }

            int finalRenamedData = renamedDataSymbols;

            // ── Phase 3: Strip ALL listing comments (most aggressive option) ──
            // This catches plate/pre/post comments at any address that may
            // mention CWE/bad/good keywords.
            Listing listing = currentProgram.getListing();
            int strippedListingComments = 0;
            for (CodeUnit cu : listing.getCodeUnits(true)) {
                for (int commentType : new int[]{
                    CodeUnit.PLATE_COMMENT, CodeUnit.PRE_COMMENT,
                    CodeUnit.POST_COMMENT, CodeUnit.EOL_COMMENT,
                    CodeUnit.REPEATABLE_COMMENT
                }) {
                    String c = cu.getComment(commentType);
                    if (c != null && LEAK_PATTERN.matcher(c).find()) {
                        cu.setComment(commentType, null);
                        strippedListingComments++;
                    }
                }
            }

            // ── Phase 4: Strip DWARF-recovered parameter and local names ──
            // Decompiler renders parameter names from the function's signature,
            // and DWARF debug info gives Juliet helpers like printLine the
            // parameter name "line". Even after the symbol rename, the
            // decompiled C still shows `void FUN_<addr>(char *line)`. Force
            // every parameter and local variable to a default `param_N` /
            // `local_N` name unless its current name is already neutral.
            int paramRenamed = 0;
            int localRenamed = 0;
            java.util.Set<String> juliet_var_names = new java.util.HashSet<>(java.util.Arrays.asList(
                "line", "data", "dataBuffer", "dataPtr", "dataPtr2",
                "badData", "goodData", "source", "sink",
                "badSource", "goodSource", "badSink", "goodSink",
                "data1", "data2", "dataGoodBuf", "dataBadBuf",
                "dataLen", "data_len", "intBuffer", "charBuffer"
            ));
            for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
                if (func.isExternal() || func.isThunk()) continue;
                try {
                    // Parameters
                    Parameter[] params = func.getParameters();
                    for (int i = 0; i < params.length; i++) {
                        Parameter p = params[i];
                        String pname = p.getName();
                        if (pname != null && (juliet_var_names.contains(pname)
                                || LEAK_PATTERN.matcher(pname).find())) {
                            try {
                                p.setName("param_" + (i + 1), SourceType.USER_DEFINED);
                                paramRenamed++;
                            } catch (Exception ignore) { }
                        }
                    }
                    // Local variables
                    Variable[] locals = func.getLocalVariables();
                    for (int i = 0; i < locals.length; i++) {
                        Variable v = locals[i];
                        String vname = v.getName();
                        if (vname != null && (juliet_var_names.contains(vname)
                                || LEAK_PATTERN.matcher(vname).find())) {
                            try {
                                v.setName("local_" + (i + 1), SourceType.USER_DEFINED);
                                localRenamed++;
                            } catch (Exception ignore) { }
                        }
                    }
                } catch (Exception e) {
                    // Some functions resist parameter editing — skip silently
                }
            }

            // ── Phase 5: Strip Juliet-style typedef / structure names ──
            // The decompiler emits user-defined struct names from DWARF in
            // signatures. Rename any Juliet-flavoured struct/typedef to a
            // neutral StructA/StructB form. We do this on the DataTypeManager.
            int typesRenamed = 0;
            try {
                ghidra.program.model.data.DataTypeManager dtm = currentProgram.getDataTypeManager();
                java.util.Iterator<ghidra.program.model.data.DataType> dtit = dtm.getAllDataTypes();
                int neutralIdx = 0;
                java.util.List<ghidra.program.model.data.DataType> dtSnap = new java.util.ArrayList<>();
                while (dtit.hasNext()) dtSnap.add(dtit.next());
                for (ghidra.program.model.data.DataType dt : dtSnap) {
                    String dtname = dt.getName();
                    if (dtname == null) continue;
                    if (LEAK_PATTERN.matcher(dtname).find()
                            || dtname.equals("charVoid") || dtname.equals("charStruct")
                            || dtname.equals("twoIntsType") || dtname.equals("intArray")) {
                        try {
                            dt.setName("StructAnon_" + (++neutralIdx));
                            typesRenamed++;
                        } catch (Exception ignore) { }
                    }
                }
            } catch (Exception e) {
                // Type-rename is best-effort; some DataTypeManagers refuse setName
            }

            currentProgram.endTransaction(tx, true);

            println("[JulietAnonymizer] DONE:");
            println("  Functions renamed:     " + renamedFunctions);
            println("  Data symbols renamed:  " + finalRenamedData);
            println("  Function comments cleared: " + clearedComments);
            println("  Listing comments stripped: " + strippedListingComments);
            println("  Parameters renamed:    " + paramRenamed);
            println("  Local vars renamed:    " + localRenamed);
            println("  Data types renamed:    " + typesRenamed);
            println("  Whitelisted skipped:   " + skippedWhitelisted);

        } catch (Exception e) {
            currentProgram.endTransaction(tx, false);
            printerr("[JulietAnonymizer] Transaction rolled back: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }

        // ── Save mapping side file (best effort, no failure if it errors) ──
        try {
            String mapPath = System.getProperty("java.io.tmpdir") +
                            "/agentg_anon_" + currentProgram.getName() + ".tsv";
            FileWriter w = new FileWriter(mapPath);
            w.write("address\toriginal_name\tanonymized_name\n");
            for (String[] row : mapping) {
                w.write(row[0] + "\t" + row[1] + "\t" + row[2] + "\n");
            }
            w.close();
            println("[JulietAnonymizer] Mapping saved: " + mapPath);
        } catch (IOException e) {
            // Non-fatal
            println("[JulietAnonymizer] Could not save mapping: " + e.getMessage());
        }
    }
}
