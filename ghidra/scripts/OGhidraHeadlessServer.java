/*
 * OGhidraHeadlessServer - GhidraScript HTTP Server
 *
 * Ported from OGhidraMCP Plugin (GhidraMCPPlugin.java) to run as a
 * GhidraScript via `analyzeHeadless -postScript OGhidraHeadlessServer.java [port]`
 *
 * Original Author: LaurieWired (https://github.com/LaurieWired/GhidraMCP)
 * Multi-Instance Architecture inspired by GhydraMCP (https://github.com/starsong/GhydraMCP)
 * Modified/Ported by: ezrealenoch
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.symbol.SourceType;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.Filter;
import java.security.SecureRandom;
import java.util.Base64;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class OGhidraHeadlessServer extends GhidraScript {

    // ── Bearer-token authentication ────────────────────────────────
    // The server generates a random token at startup and writes it to a
    // sidecar file in the project's tmp dir so the Python tool runner can
    // read it and add the Authorization header to every request. The
    // token gates ALL endpoints except /health (which only returns
    // [redacted] anyway and is needed for readiness probing).
    //
    // Token can also be supplied via:
    //   1. -postScript arg #2 (after the port)
    //   2. environment variable AGENT_G_GHIDRA_AUTH_TOKEN
    //   3. auto-generated 32-byte URL-safe random
    //
    // Disable by setting AGENT_G_GHIDRA_AUTH_DISABLE=1 (NOT recommended
    // outside of localhost benchmarking).
    private static String authToken = null;
    private static boolean authEnabled = true;
    private static final java.util.Set<String> AUTH_EXEMPT = new java.util.HashSet<>(
        java.util.Arrays.asList("/health")
    );


    private HttpServer server;
    private volatile boolean shutdownRequested = false;
    private final Object txLock = new Object();
    private final AtomicLong lastActivity = new AtomicLong(System.currentTimeMillis());

    private static final int DEFAULT_PORT = 8080;
    private static final int MAX_PORT_ATTEMPTS = 10;
    private static final int DYNAMIC_PORT_START = 8192;

    // ==================================================================================
    // Inner classes
    // ==================================================================================

    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    // ==================================================================================
    // Main entry point
    // ==================================================================================

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        int requestedPort = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;

        int actualPort = findAvailablePort(requestedPort);

        // Initialize bearer auth before binding endpoints so registerEndpoints
        // can attach the auth filter consistently to every protected context.
        initAuthToken(args, actualPort);

        server = HttpServer.create(new InetSocketAddress(actualPort), 0);
        registerEndpoints(actualPort);
        server.setExecutor(null);
        server.start();

        long IDLE_TIMEOUT_MS = 30L * 60 * 1000; // 30 minutes
        println("OGhidra HTTP server ready on port " + actualPort);

        while (!shutdownRequested && !monitor.isCancelled()) {
            Thread.sleep(500);
            if (System.currentTimeMillis() - lastActivity.get() > IDLE_TIMEOUT_MS) {
                println("Idle timeout reached. Shutting down.");
                break;
            }
        }

        server.stop(2);
        println("Server stopped.");
    }

    // ==================================================================================
    // Port allocation
    // ==================================================================================

    private int findAvailablePort(int basePort) {
        if (basePort != DEFAULT_PORT) {
            if (isPortAvailable(basePort))
                return basePort;
            println("WARNING: Configured port " + basePort + " is in use. Falling back to dynamic allocation.");
        }

        if (isPortAvailable(DEFAULT_PORT)) {
            return DEFAULT_PORT;
        }

        for (int i = 0; i < MAX_PORT_ATTEMPTS; i++) {
            int candidate = DYNAMIC_PORT_START + i;
            if (isPortAvailable(candidate)) {
                return candidate;
            }
        }

        throw new RuntimeException("Could not find open port: " + DEFAULT_PORT + " or " + DYNAMIC_PORT_START + "+");
    }

    private boolean isPortAvailable(int port) {
        try (ServerSocket s = new ServerSocket(port)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    // ==================================================================================
    // Authentication
    // ==================================================================================

    /**
     * Initialize the bearer auth token. Order of precedence:
     *   1. AGENT_G_GHIDRA_AUTH_DISABLE=1 → disable auth entirely (DEV ONLY)
     *   2. -postScript second arg ($1) → use that as the token
     *   3. AGENT_G_GHIDRA_AUTH_TOKEN env var → use that as the token
     *   4. Auto-generate a 32-byte URL-safe random token
     *
     * The token is also written to a sidecar file at:
     *   {temp_dir}/agent_g_ghidra_token_{port}.txt
     * so the Python tool runner can read it without parsing logs.
     */
    private void initAuthToken(String[] args, int port) {
        if ("1".equals(System.getenv("AGENT_G_GHIDRA_AUTH_DISABLE"))) {
            authEnabled = false;
            println("[auth] DISABLED via AGENT_G_GHIDRA_AUTH_DISABLE — endpoints unauthenticated");
            return;
        }
        if (args.length >= 2 && args[1] != null && !args[1].isEmpty()) {
            authToken = args[1];
        } else {
            String envTok = System.getenv("AGENT_G_GHIDRA_AUTH_TOKEN");
            if (envTok != null && !envTok.isEmpty()) {
                authToken = envTok;
            } else {
                byte[] buf = new byte[32];
                new SecureRandom().nextBytes(buf);
                authToken = Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
            }
        }
        // Write token to sidecar file the Python client can read
        try {
            String tmp = System.getProperty("java.io.tmpdir");
            java.nio.file.Path p = java.nio.file.Paths.get(
                tmp, "agent_g_ghidra_token_" + port + ".txt");
            java.nio.file.Files.write(p, authToken.getBytes("UTF-8"));
            println("[auth] token sidecar: " + p.toString());
        } catch (Exception e) {
            println("[auth] WARNING: failed to write token sidecar: " + e.getMessage());
        }
        println("[auth] bearer token enabled (" + authToken.length() + " chars)");
    }

    /** HTTP filter that enforces the Authorization: Bearer header. */
    private Filter authFilter = new Filter() {
        @Override public String description() { return "AgentG bearer auth"; }
        @Override
        public void doFilter(HttpExchange ex, Filter.Chain chain) throws IOException {
            if (!authEnabled) { chain.doFilter(ex); return; }
            String path = ex.getRequestURI().getPath();
            if (AUTH_EXEMPT.contains(path)) { chain.doFilter(ex); return; }
            String h = ex.getRequestHeaders().getFirst("Authorization");
            if (h == null || !h.startsWith("Bearer ")) {
                deny(ex, "missing bearer");
                return;
            }
            String tok = h.substring("Bearer ".length()).trim();
            // Constant-time compare
            if (!constantTimeEquals(tok, authToken)) {
                deny(ex, "invalid token");
                return;
            }
            chain.doFilter(ex);
        }
    };

    private void deny(HttpExchange ex, String reason) throws IOException {
        byte[] body = ("{\"error\":\"unauthorized\",\"reason\":\"" + reason + "\"}").getBytes("UTF-8");
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(401, body.length);
        ex.getResponseBody().write(body);
        ex.getResponseBody().close();
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        if (a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) diff |= a.charAt(i) ^ b.charAt(i);
        return diff == 0;
    }

    /**
     * Wrap server.createContext() so every protected endpoint automatically
     * receives the auth filter. This replaces direct server.createContext()
     * calls throughout the file.
     */
    private HttpContext protectedContext(String path,
            com.sun.net.httpserver.HttpHandler handler) {
        HttpContext ctx = server.createContext(path, handler);
        ctx.getFilters().add(authFilter);
        return ctx;
    }

    // ==================================================================================
    // Endpoint registration
    // ==================================================================================

    private void registerEndpoints(final int actualPort) {

        // --- Health / Shutdown ---

        protectedContext("/health", exchange -> {
            touchActivity();
            // SECURITY: do NOT leak the original program name. The model can
            // call /health at any time and the original Juliet path would
            // give away the ground truth (e.g. CWE121_..._01_bad). Always
            // return a generic "[redacted]" program token. The actual loaded
            // program is still tracked internally for tool dispatch.
            String json = "{\"status\":\"ready\",\"mode\":\"headless\",\"program\":\"[redacted]\""
                    + ",\"port\":" + actualPort + "}";
            sendJsonResponse(exchange, json);
        });

        protectedContext("/shutdown", exchange -> {
            touchActivity();
            shutdownRequested = true;
            sendJsonResponse(exchange, "{\"status\":\"shutting_down\"}");
        });

        // --- Discovery endpoints ---

        protectedContext("/plugin-version", exchange -> {
            touchActivity();
            String json = "{\"result\": {\"plugin_version\": \"OGhidra-Headless\", \"api_version\": \"1.0\"}}";
            sendJsonResponse(exchange, json);
        });

        protectedContext("/program", exchange -> {
            touchActivity();
            // SECURITY: same redaction as /health. Never return the
            // original filename to a caller. We still expose a stable
            // synthetic program id derived from the project locator hash
            // so callers that key on programId across requests still work.
            if (currentProgram != null) {
                String json = "{\"result\": {\"name\": \"[redacted]\", \"programId\": \"[redacted]\"}}";
                sendJsonResponse(exchange, json);
            } else {
                sendJsonResponse(exchange, "{\"result\": {}}");
            }
        });

        // --- Listing endpoints ---

        protectedContext("/methods", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        protectedContext("/classes", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        protectedContext("/decompile", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name, offset, limit));
        });

        protectedContext("/renameFunction", exchange -> {
            touchActivity();
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully"
                    : "Rename failed";
            sendResponse(exchange, response);
        });

        protectedContext("/renameData", exchange -> {
            touchActivity();
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        protectedContext("/renameVariable", exchange -> {
            touchActivity();
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        protectedContext("/segments", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        protectedContext("/imports", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listImports(offset, limit));
        });

        protectedContext("/exports", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listExports(offset, limit));
        });

        protectedContext("/namespaces", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        protectedContext("/data", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        protectedContext("/searchFunctions", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // --- Address-based endpoints ---

        protectedContext("/get_function_by_address", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        protectedContext("/get_current_address", exchange -> {
            touchActivity();
            sendResponse(exchange, "Not available in headless mode \u2014 use address-based endpoints");
        });

        protectedContext("/get_current_function", exchange -> {
            touchActivity();
            sendResponse(exchange, "Not available in headless mode \u2014 use address-based endpoints");
        });

        protectedContext("/list_functions", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listFunctions(offset, limit));
        });

        protectedContext("/decompile_function", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, decompileFunctionByAddress(address, offset, limit));
        });

        protectedContext("/disassemble_function", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        protectedContext("/set_decompiler_comment", exchange -> {
            touchActivity();
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        protectedContext("/set_disassembly_comment", exchange -> {
            touchActivity();
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        protectedContext("/rename_function_by_address", exchange -> {
            touchActivity();
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        protectedContext("/set_function_prototype", exchange -> {
            touchActivity();
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        protectedContext("/set_local_variable_type", exchange -> {
            touchActivity();
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                    .append(" to ").append(newType)
                    .append(" in function at ").append(functionAddress).append("\n\n");

            if (currentProgram != null) {
                DataTypeManager dtm = currentProgram.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        protectedContext("/xrefs_to", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        protectedContext("/xrefs_from", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        protectedContext("/function_xrefs", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        protectedContext("/strings", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        protectedContext("/read_bytes", exchange -> {
            touchActivity();
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 16);
            String format = qparams.getOrDefault("format", "hex");
            sendResponse(exchange, readBytesFromAddress(address, length, format));
        });
    }

    // ==================================================================================
    // Activity tracking
    // ==================================================================================

    private void touchActivity() {
        lastActivity.set(System.currentTimeMillis());
    }

    // ==================================================================================
    // Listing / query helpers
    // ==================================================================================

    private String getAllFunctionNames(int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : currentProgram.getSymbolTable().getExternalSymbols()) {
            StringBuilder line = new StringBuilder();
            line.append(symbol.getName()).append(" -> ").append(symbol.getAddress());

            ReferenceIterator refIter = currentProgram.getReferenceManager().getReferencesTo(symbol.getAddress());
            List<String> callers = new ArrayList<>();
            int refCount = 0;

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                refCount++;
                if (refCount <= 5) {
                    Address fromAddr = ref.getFromAddress();
                    Function caller = currentProgram.getFunctionManager().getFunctionContaining(fromAddr);
                    if (caller != null) {
                        callers.add(caller.getName());
                    } else {
                        callers.add(fromAddr.toString());
                    }
                }
            }

            if (refCount > 0) {
                line.append(" [Refs: ").append(refCount).append("]");
                if (!callers.isEmpty()) {
                    line.append(" [Callers: ").append(String.join(", ", callers));
                    if (refCount > 5) {
                        line.append(", ...");
                    }
                    line.append("]");
                }
            }

            lines.add(line.toString());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";

        SymbolTable table = currentProgram.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            DataIterator it = currentProgram.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                            data.getAddress(),
                            escapeNonAscii(label),
                            escapeNonAscii(valRepr)));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty())
            return "Search term is required";

        List<String> matches = new ArrayList<>();
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }

        Collections.sort(matches);

        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }

    // ==================================================================================
    // Function query methods
    // ==================================================================================

    private String getFunctionByAddress(String addressStr) {
        if (currentProgram == null)
            return "No program loaded";
        if (addressStr == null || addressStr.isEmpty())
            return "Address is required";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);

            if (func == null)
                return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                    func.getName(),
                    func.getEntryPoint(),
                    func.getSignature(),
                    func.getEntryPoint(),
                    func.getBody().getMinAddress(),
                    func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    private String listFunctions(int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";

        List<String> functions = new ArrayList<>();
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            functions.add(String.format("%s at %s",
                    func.getName(),
                    func.getEntryPoint()));
        }

        return paginateList(functions, offset, limit);
    }

    private Function getFunctionForAddress(Address addr) {
        Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = currentProgram.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    // ==================================================================================
    // Decompile / Disassemble
    // ==================================================================================

    private String decompileFunctionByName(String name, int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result = decomp.decompileFunction(func, 30, monitor);
                if (result != null && result.decompileCompleted()) {
                    return paginateString(result.getDecompiledFunction().getC(), offset, limit);
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private String decompileFunctionByAddress(String addressStr, int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";
        if (addressStr == null || addressStr.isEmpty())
            return "Address is required";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(addr);
            if (func == null)
                return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            DecompileResults result = decomp.decompileFunction(func, 30, monitor);

            String code = (result != null && result.decompileCompleted())
                    ? result.getDecompiledFunction().getC()
                    : "Decompilation failed";

            return paginateString(code, offset, limit);
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    private String disassembleFunction(String addressStr) {
        if (currentProgram == null)
            return "No program loaded";
        if (addressStr == null || addressStr.isEmpty())
            return "Address is required";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(addr);
            if (func == null)
                return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = currentProgram.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break;
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n",
                        instr.getAddress(),
                        instr.toString(),
                        comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }

    private DecompileResults decompileFunction(Function func) {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        decomp.setSimplificationStyle("decompile");

        DecompileResults results = decomp.decompileFunction(func, 60, monitor);

        if (!results.decompileCompleted()) {
            printerr("Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    // ==================================================================================
    // Mutation methods (rename, set comment, set prototype, set variable type)
    // All wrapped in synchronized(txLock) instead of SwingUtilities.invokeAndWait
    // ==================================================================================

    private boolean renameFunction(String oldName, String newName) {
        if (currentProgram == null)
            return false;

        synchronized (txLock) {
            int tx = currentProgram.startTransaction("Rename function via HTTP");
            boolean success = false;
            try {
                for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
                    if (func.getName().equals(oldName)) {
                        func.setName(newName, SourceType.USER_DEFINED);
                        success = true;
                        break;
                    }
                }
                currentProgram.endTransaction(tx, success);
            } catch (Exception e) {
                currentProgram.endTransaction(tx, false);
                printerr("Error renaming function: " + e.getMessage());
            }
            return success;
        }
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        if (currentProgram == null)
            return;

        synchronized (txLock) {
            int tx = currentProgram.startTransaction("Rename data");
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                Listing listing = currentProgram.getListing();
                Data data = listing.getDefinedDataAt(addr);
                if (data != null) {
                    SymbolTable symTable = currentProgram.getSymbolTable();
                    Symbol symbol = symTable.getPrimarySymbol(addr);
                    if (symbol != null) {
                        symbol.setName(newName, SourceType.USER_DEFINED);
                    } else {
                        symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                    }
                }
                currentProgram.endTransaction(tx, true);
            } catch (Exception e) {
                currentProgram.endTransaction(tx, false);
                printerr("Rename data error: " + e.getMessage());
            }
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        if (currentProgram == null)
            return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Function func = null;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, monitor);
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();

            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        synchronized (txLock) {
            int tx = currentProgram.startTransaction("Rename variable");
            boolean success = false;
            try {
                if (commitRequired) {
                    HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, func.getSignatureSource());
                }
                HighFunctionDBUtil.updateDBVariable(
                        highSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED);
                success = true;
                currentProgram.endTransaction(tx, true);
            } catch (Exception e) {
                currentProgram.endTransaction(tx, false);
                String errorMsg = "Failed to rename variable: " + e.getMessage();
                printerr(errorMsg);
                return errorMsg;
            }
            return success ? "Variable renamed" : "Failed to rename variable";
        }
    }

    protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }
        Function function = hfunction.getFunction();
        Parameter[] parameters = function.getParameters();
        LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) {
            return true;
        }

        for (int i = 0; i < numParams; i++) {
            HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) {
                return true;
            }
            VariableStorage storage = param.getStorage();
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
                return true;
            }
        }

        return false;
    }

    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        if (currentProgram == null)
            return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null)
            return false;

        synchronized (txLock) {
            int tx = currentProgram.startTransaction(transactionName);
            boolean success = false;
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                currentProgram.getListing().setComment(addr, commentType, comment);
                success = true;
                currentProgram.endTransaction(tx, true);
            } catch (Exception e) {
                currentProgram.endTransaction(tx, false);
                printerr("Error setting " + transactionName.toLowerCase() + ": " + e.getMessage());
            }
            return success;
        }
    }

    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        if (currentProgram == null)
            return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
                newName == null || newName.isEmpty()) {
            return false;
        }

        synchronized (txLock) {
            int tx = currentProgram.startTransaction("Rename function by address");
            boolean success = false;
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(functionAddrStr);
                Function func = getFunctionForAddress(addr);

                if (func == null) {
                    printerr("Could not find function at address: " + functionAddrStr);
                    currentProgram.endTransaction(tx, false);
                    return false;
                }

                func.setName(newName, SourceType.USER_DEFINED);
                success = true;
                currentProgram.endTransaction(tx, true);
            } catch (Exception e) {
                currentProgram.endTransaction(tx, false);
                printerr("Error renaming function by address: " + e.getMessage());
            }
            return success;
        }
    }

    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        if (currentProgram == null)
            return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        boolean success = false;

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                return new PrototypeResult(false, msg);
            }

            println("Setting prototype for function " + func.getName() + ": " + prototype);

            // Add prototype comment
            synchronized (txLock) {
                int txComment = currentProgram.startTransaction("Add prototype comment");
                try {
                    currentProgram.getListing().setComment(
                            func.getEntryPoint(),
                            CodeUnit.PLATE_COMMENT,
                            "Setting prototype: " + prototype);
                    currentProgram.endTransaction(txComment, true);
                } catch (Exception e) {
                    currentProgram.endTransaction(txComment, false);
                }
            }

            // Parse and apply
            synchronized (txLock) {
                int txProto = currentProgram.startTransaction("Set function prototype");
                try {
                    DataTypeManager dtm = currentProgram.getDataTypeManager();

                    // Pass null for DataTypeManagerService (not available in headless mode)
                    ghidra.app.util.parser.FunctionSignatureParser parser =
                            new ghidra.app.util.parser.FunctionSignatureParser(dtm, null);

                    ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

                    if (sig == null) {
                        String msg = "Failed to parse function prototype";
                        errorMessage.append(msg);
                        currentProgram.endTransaction(txProto, false);
                        return new PrototypeResult(false, errorMessage.toString());
                    }

                    ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                            new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                                    addr, sig, SourceType.USER_DEFINED);

                    boolean cmdResult = cmd.applyTo(currentProgram, monitor);

                    if (cmdResult) {
                        success = true;
                        println("Successfully applied function signature");
                    } else {
                        String msg = "Command failed: " + cmd.getStatusMsg();
                        errorMessage.append(msg);
                        printerr(msg);
                    }

                    currentProgram.endTransaction(txProto, success);
                } catch (Exception e) {
                    currentProgram.endTransaction(txProto, false);
                    String msg = "Error applying function signature: " + e.getMessage();
                    errorMessage.append(msg);
                    printerr(msg);
                }
            }
        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            printerr(msg);
        }

        return new PrototypeResult(success, errorMessage.toString());
    }

    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        if (currentProgram == null)
            return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
                variableName == null || variableName.isEmpty() ||
                newType == null || newType.isEmpty()) {
            return false;
        }

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(addr);

            if (func == null) {
                printerr("Could not find function at address: " + functionAddrStr);
                return false;
            }

            DecompileResults results = decompileFunction(func);
            if (results == null || !results.decompileCompleted()) {
                return false;
            }

            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                printerr("No high function available");
                return false;
            }

            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                printerr("Could not find variable '" + variableName + "' in decompiled function");
                return false;
            }

            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                printerr("No HighVariable found for symbol: " + variableName);
                return false;
            }

            println("Found high variable for: " + variableName +
                    " with current type " + highVar.getDataType().getName());

            DataTypeManager dtm = currentProgram.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                printerr("Could not resolve data type: " + newType);
                return false;
            }

            println("Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply in transaction
            synchronized (txLock) {
                int tx = currentProgram.startTransaction("Set variable type");
                boolean success = false;
                try {
                    HighFunctionDBUtil.updateDBVariable(
                            symbol,
                            symbol.getName(),
                            dataType,
                            SourceType.USER_DEFINED);
                    success = true;
                    println("Successfully set variable type using HighFunctionDBUtil");
                    currentProgram.endTransaction(tx, true);
                } catch (Exception e) {
                    currentProgram.endTransaction(tx, false);
                    printerr("Error setting variable type: " + e.getMessage());
                }
                return success;
            }
        } catch (Exception e) {
            printerr("Error setting variable type: " + e.getMessage());
            return false;
        }
    }

    private HighSymbol findSymbolByName(HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    // ==================================================================================
    // Xrefs
    // ==================================================================================

    private String getXrefsTo(String addressStr, int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";
        if (addressStr == null || addressStr.isEmpty())
            return "Address is required";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "Error: Invalid address format or address not found: " + addressStr;
            }
            ReferenceManager refManager = currentProgram.getReferenceManager();

            ReferenceIterator refIter = refManager.getReferencesTo(addr);

            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = currentProgram.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }

            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    private String getXrefsFrom(String addressStr, int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";
        if (addressStr == null || addressStr.isEmpty())
            return "Address is required";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "Error: Invalid address format or address not found: " + addressStr;
            }
            ReferenceManager refManager = currentProgram.getReferenceManager();

            Reference[] references = refManager.getReferencesFrom(addr);

            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();

                String targetInfo = "";
                Function toFunc = currentProgram.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = currentProgram.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }

                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }

            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    private String getFunctionXrefs(String functionName, int offset, int limit) {
        if (currentProgram == null)
            return "No program loaded";
        if (functionName == null || functionName.isEmpty())
            return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = currentProgram.getFunctionManager();
            ReferenceManager refManager = currentProgram.getReferenceManager();
            SymbolTable symbolTable = currentProgram.getSymbolTable();

            Address targetAddress = null;
            String targetType = "function";

            // First, try to find as a regular function
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    targetAddress = function.getEntryPoint();
                    break;
                }
            }

            // If not found, check external symbols (imports)
            if (targetAddress == null) {
                for (Symbol symbol : symbolTable.getExternalSymbols()) {
                    if (symbol.getName().equals(functionName)) {
                        targetAddress = symbol.getAddress();
                        targetType = "external";
                        break;
                    }
                }
            }

            // Still not found? Try all symbols matching the name
            if (targetAddress == null) {
                SymbolIterator symIt = symbolTable.getSymbols(functionName);
                if (symIt.hasNext()) {
                    Symbol symbol = symIt.next();
                    targetAddress = symbol.getAddress();
                    targetType = symbol.getSymbolType().toString().toLowerCase();
                }
            }

            if (targetAddress == null) {
                return "Function or symbol not found: " + functionName;
            }

            ReferenceIterator refIter = refManager.getReferencesTo(targetAddress);

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }

            if (refs.isEmpty()) {
                return "No references found to " + targetType + ": " + functionName + " (at " + targetAddress + ")";
            }

            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

    // ==================================================================================
    // Strings
    // ==================================================================================

    private String listDefinedStrings(int offset, int limit, String filter) {
        if (currentProgram == null)
            return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = currentProgram.getListing().getDefinedData(true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();

            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";

                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }

        return paginateList(lines, offset, limit);
    }

    private boolean isStringData(Data data) {
        if (data == null)
            return false;

        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    // ==================================================================================
    // Raw byte reading
    // ==================================================================================

    private String readBytesFromAddress(String addressStr, int length, String format) {
        if (currentProgram == null)
            return "No program loaded";
        if (addressStr == null || addressStr.isEmpty())
            return "Address is required";
        if (length <= 0 || length > 4096)
            return "Length must be 1-4096 bytes";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null)
                return "Invalid address: " + addressStr;

            byte[] bytes = new byte[length];
            int bytesRead = currentProgram.getMemory().getBytes(addr, bytes);

            if (bytesRead <= 0)
                return "Could not read bytes at address: " + addressStr;

            if ("raw".equals(format)) {
                return java.util.Base64.getEncoder().encodeToString(
                        java.util.Arrays.copyOf(bytes, bytesRead));
            }

            // Default: hex dump
            return formatHexDump(addr, bytes, bytesRead);
        } catch (ghidra.program.model.mem.MemoryAccessException e) {
            return "Memory access error at " + addressStr + ": " + e.getMessage();
        } catch (Exception e) {
            return "Error reading bytes: " + e.getMessage();
        }
    }

    private String formatHexDump(Address startAddr, byte[] bytes, int length) {
        StringBuilder sb = new StringBuilder();
        int bytesPerLine = 16;

        for (int i = 0; i < length; i += bytesPerLine) {
            sb.append(String.format("%s: ", startAddr.add(i)));

            for (int j = 0; j < bytesPerLine && (i + j) < length; j++) {
                sb.append(String.format("%02X ", bytes[i + j] & 0xFF));
            }

            for (int j = length - i; j < bytesPerLine && i + bytesPerLine > length; j++) {
                sb.append("   ");
            }

            sb.append(" |");
            for (int j = 0; j < bytesPerLine && (i + j) < length; j++) {
                byte b = bytes[i + j];
                sb.append((b >= 32 && b < 127) ? (char) b : '.');
            }
            sb.append("|\n");
        }
        return sb.toString();
    }

    // ==================================================================================
    // Data type resolution
    // ==================================================================================

    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            println("Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            println("WARNING: Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }
                println("WARNING: Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }

    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt.getName().equals(name)) {
                return dt;
            }
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ==================================================================================
    // Utility: parsing, pagination, HTTP responses
    // ==================================================================================

    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery();
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=", 2);
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = "";
                    if (kv.length == 2) {
                        value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    }
                    if (!key.isEmpty()) {
                        result.put(key, value);
                    }
                } catch (Exception e) {
                    printerr("Error decoding URL parameter: " + p + " - " + e.getMessage());
                }
            }
        }
        return result;
    }

    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    printerr("Error decoding URL parameter: " + e.getMessage());
                }
            }
        }
        return params;
    }

    private String paginateList(List<String> items, int offset, int limit) {
        int total = items.size();
        int start = Math.max(0, offset);
        int end = Math.min(total, offset + limit);

        if (start >= total) {
            return String.format("[Total: %d] [Showing: 0 items - offset %d exceeds total]", total, offset);
        }

        List<String> sub = items.subList(start, end);
        String content = String.join("\n", sub);

        StringBuilder header = new StringBuilder();
        header.append(String.format("[Total: %d] [Showing: %d-%d]", total, start + 1, end));

        if (end < total) {
            header.append(String.format(" [Next: offset=%d, limit=%d]", end, limit));
        }

        return header.toString() + "\n" + content;
    }

    private String paginateString(String content, int offset, int limit) {
        if (content == null)
            return "";
        content = content.trim();
        String[] lines = content.split("\\r?\\n");
        int total = lines.length;
        int start = Math.max(0, offset);
        int end = Math.min(total, offset + limit);

        if (start >= total) {
            return String.format("[Total Lines: %d] [Showing: 0 lines - offset %d exceeds total]", total, offset);
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[Total Lines: %d] [Showing Lines: %d-%d]\n", total, start + 1, end));

        for (int i = start; i < end; i++) {
            sb.append(lines[i]).append("\n");
        }

        if (end < total) {
            sb.append(String.format("... [Next: offset=%d, limit=%d]", end, limit));
        }

        return sb.toString();
    }

    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null)
            return defaultValue;
        try {
            return Integer.parseInt(val);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private String escapeNonAscii(String input) {
        if (input == null)
            return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    private String escapeString(String input) {
        if (input == null)
            return "";

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int) c & 0xFF));
            }
        }
        return sb.toString();
    }

    private String escapeJsonString(String input) {
        if (input == null)
            return "";
        return input.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendJsonResponse(HttpExchange exchange, String jsonResponse) throws IOException {
        byte[] bytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
