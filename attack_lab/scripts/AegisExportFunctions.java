// AEGIS Ghidra 12.1.x headless post-script. No third-party JSON libraries.
// Script arguments: output_json, exact_function_or_*, max_functions, max_c_chars, decompile_timeout_seconds
// Output fields must match aegis_lab.ghidra.RawAnalysis / FunctionEvidence (aegis.lab.ghidra.v1).
// Headless only: extends HeadlessScript so it can report whether auto-analysis timed out.
// @category AEGIS

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;

public class AegisExportFunctions extends HeadlessScript {
    // Bound for decompiler messages and failure reasons (UTF-16 code units);
    // must equal aegis_lab.ghidra.MAX_DECOMPILER_MESSAGE_CHARS.
    private static final int MAX_MESSAGE_CHARS = 2000;

    // Lone UTF-16 surrogates are replaced so the output is always valid UTF-8 JSON.
    private static String escape(String value) {
        if (value == null) value = "";
        StringBuilder result = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < value.length()
                    && Character.isLowSurrogate(value.charAt(i + 1))) {
                result.append(c).append(value.charAt(++i));
                continue;
            }
            if (Character.isSurrogate(c)) {
                result.append("\\ufffd");
                continue;
            }
            switch (c) {
                case '\"': result.append("\\\""); break;
                case '\\': result.append("\\\\"); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (c < 0x20 || c == 0x2028 || c == 0x2029) {
                        result.append(String.format("\\u%04x", (int)c));
                    } else {
                        result.append(c);
                    }
            }
        }
        return result.append('"').toString();
    }

    // Truncate without splitting a surrogate pair.
    private static String truncate(String code, int maxChars) {
        int end = maxChars;
        if (end > 0 && Character.isHighSurrogate(code.charAt(end - 1))) end--;
        return code.substring(0, end);
    }

    private static int boundedInt(String value, int min, int max) {
        int n = Integer.parseInt(value);
        if (n < min || n > max) throw new IllegalArgumentException("integer out of range");
        return n;
    }

    // Ghidra reports decompiler warnings through getErrorMessage() even when
    // decompilation succeeds, so the message is kept independently of success.
    private static String decompilerMessage(DecompileResults results) {
        if (results == null) return "";
        String message = results.getErrorMessage();
        return message == null ? "" : message.strip();
    }

    private static String failureStatus(DecompileResults results) {
        if (results == null) return "failed";
        if (results.isTimedOut()) return "timed_out";
        if (results.isCancelled()) return "cancelled";
        if (results.failedToStart()) return "failed_to_start";
        return "failed";
    }

    private static String failureReason(DecompileResults results, String message, int timeout) {
        if (results == null) return "null decompile result";
        if (results.isTimedOut()) return "decompiler timed out after " + timeout + "s";
        if (results.isCancelled()) return "decompilation cancelled";
        if (results.failedToStart()) return "decompiler failed to start";
        if (message.isEmpty()) return "decompiler returned no function";
        return message.length() > MAX_MESSAGE_CHARS ? truncate(message, MAX_MESSAGE_CHARS) : message;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5) throw new IllegalArgumentException("expected 5 script arguments");
        File target = new File(args[0]);
        if (!target.isAbsolute()) throw new IllegalArgumentException("output path must be absolute");
        String selector = args[1];
        int maxFunctions = boundedInt(args[2], 1, 512);
        int maxChars = boundedInt(args[3], 100, 20000);
        int timeout = boundedInt(args[4], 1, 120);
        if (currentProgram == null) throw new IllegalStateException("no imported program");
        boolean analysisTimedOut = analysisTimeoutOccurred();
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("decompiler could not open program: "
                + decompiler.getLastMessage());
        }
        try {
            StringBuilder out = new StringBuilder(16384);
            out.append("{\"schema_version\":\"aegis.lab.ghidra.v1\"");
            out.append(",\"ghidra_version\":").append(escape(Application.getApplicationVersion()));
            out.append(",\"ghidra_release_name\":").append(escape(Application.getApplicationReleaseName()));
            out.append(",\"ghidra_build_date\":").append(escape(Application.getBuildDate()));
            out.append(",\"java_version\":").append(escape(System.getProperty("java.version")));
            out.append(",\"analysis_timed_out\":").append(analysisTimedOut ? "true" : "false");
            out.append(",\"program_name\":").append(escape(currentProgram.getName()));
            out.append(",\"executable_sha256\":").append(escape(currentProgram.getExecutableSHA256()));
            out.append(",\"executable_format\":").append(escape(currentProgram.getExecutableFormat()));
            out.append(",\"language_id\":").append(escape(currentProgram.getLanguageID().toString()));
            out.append(",\"functions\":[");
            int included = 0;
            int matching = 0;
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                monitor.checkCancelled();
                Function fn = functions.next();
                if (fn.isExternal()) continue;
                if (!"*".equals(selector) && !selector.equals(fn.getName())
                        && !selector.equals(fn.getName(true))) continue;
                matching++;
                if (included >= maxFunctions) continue;
                DecompileResults results = decompiler.decompileFunction(fn, timeout, monitor);
                boolean success = results != null && results.decompileCompleted()
                    && results.getDecompiledFunction() != null
                    && results.getDecompiledFunction().getC() != null
                    && !results.getDecompiledFunction().getC().isEmpty();
                String code = success ? results.getDecompiledFunction().getC() : "";
                String decompilerSignature = success ? results.getDecompiledFunction().getSignature() : "";
                boolean truncated = code.length() > maxChars;
                if (truncated) code = truncate(code, maxChars);
                String message = decompilerMessage(results);
                String error = success ? "" : failureReason(results, message, timeout);
                String status = success ? (message.isEmpty() ? "completed" : "completed_with_warnings")
                    : failureStatus(results);
                boolean messageTruncated = message.length() > MAX_MESSAGE_CHARS;
                if (messageTruncated) message = truncate(message, MAX_MESSAGE_CHARS);
                if (included != 0) out.append(',');
                out.append("{\"name\":").append(escape(fn.getName()));
                out.append(",\"qualified_name\":").append(escape(fn.getName(true)));
                out.append(",\"entry_point\":").append(escape(fn.getEntryPoint().toString()));
                out.append(",\"is_thunk\":").append(fn.isThunk() ? "true" : "false");
                out.append(",\"signature\":").append(escape(fn.getPrototypeString(false, false)));
                out.append(",\"decompiler_signature\":").append(escape(decompilerSignature));
                out.append(",\"decompile_success\":").append(success ? "true" : "false");
                out.append(",\"decompile_status\":").append(escape(status));
                out.append(",\"decompiled_c\":").append(escape(code));
                out.append(",\"decompiled_c_truncated\":").append(truncated ? "true" : "false");
                out.append(",\"decompiler_message\":").append(escape(message));
                out.append(",\"decompiler_message_truncated\":").append(messageTruncated ? "true" : "false");
                out.append(",\"error\":").append(escape(error));
                out.append('}');
                included++;
            }
            out.append("],\"matching_function_count\":").append(matching);
            out.append(",\"functions_limited\":").append(matching > maxFunctions ? "true" : "false");
            out.append('}');
            // CREATE_NEW: never follow or replace an existing file at the target path.
            try (BufferedWriter writer = Files.newBufferedWriter(target.toPath(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                writer.write(out.toString());
            }
            println("AEGIS: exported " + included + " of " + matching + " matching functions");
        } finally {
            decompiler.dispose();
        }
    }
}
