"""LeakFilter — wraps a ToolRunner to strip Juliet test-suite leaks.

The Juliet anonymizer (JulietAnonymizer.java) handles symbol-level leaks
in Ghidra's database. But the binary's actual data section may still contain
strings like "Calling bad()..." that the agent could read via list_strings,
and the decompiler will render those same strings inline as function-call
arguments via decompile_function_by_address.

This filter intercepts BOTH list_strings AND decompile_function_by_address
results and either drops leaky lines (list_strings) or replaces leaky string
literals inside the C source with [FILTERED] (decompile output). It is a
drop-in replacement for ToolRunner — duck-typed to expose the same
``execute(name, params) -> (str, bool)`` interface.
"""

import logging
import re

logger = logging.getLogger("agent-g.leak_filter")


# Patterns that indicate Juliet test scaffolding leaks. Used both for
# string-table line dropping and for masking inside decompile output.
LEAK_PATTERNS = re.compile(
    r"(?i)("
    r"cwe[-_ ]?\d+|"                           # CWE-121, CWE_121, CWE 121
    r"stack[-_ ]based|heap[-_ ]based|"
    r"buffer[-_ ]over|buffer[-_ ]under|"
    r"use[-_ ]after[-_ ]free|double[-_ ]free|"
    r"null[-_ ]?deref|format[-_ ]string|"
    r"integer[-_ ]over|integer[-_ ]under|"
    r"divide[-_ ]by[-_ ]zero|memory[-_ ]leak|"
    r"calling bad|calling good|"               # Test scaffolding output
    r"finished bad|finished good|"
    r"good[GB]\d?[GB]?|"                       # goodG2B, goodB2G
    r"\bbad\d*\b|\bgood\d*\b|"                 # standalone bad/good identifiers
    r"juliet|"
    r"testcase[_-]?support|"
    # Juliet helper / I/O scaffold function names
    r"printLine|printIntLine|printLongLine|printLongLongLine|printSizeTLine|"
    r"printHexCharLine|printIntPointerLine|printDoubleLine|printFloatLine|"
    r"printStructLine|printStruct|"
    r"decodeHex|globalReturns|globalArgc|globalArgv|"
    r"goodG2B[12]?|goodB2G[12]?|"
    r"good_?source|bad_?source|good_?sink|bad_?sink|"
    r"omitbad|omitgood"
    r")"
)

# Regex that finds C double-quoted string literals inside decompiled C code.
# Conservative: matches "..." with no embedded newlines, allowing escaped
# quotes via simple [^"\\] | \\. classes. This is good enough for the
# decompiler's rendering of constant string args, which never spans lines.
_C_STRING_LITERAL = re.compile(r'"((?:[^"\\\n]|\\.)*)"')

# Regex that finds Juliet-style typedef / struct field names that the
# decompiler may render in signatures even after symbol renaming. We replace
# these with neutral type names so the model doesn't pattern-match on them.
_DECOMP_TYPEDEF_REPLACEMENTS = [
    (re.compile(r'\bcharVoid\b'), 'StructA'),
    (re.compile(r'\bcharStruct\b'), 'StructB'),
    (re.compile(r'\btwoIntsType\b'), 'StructC'),
    (re.compile(r'\bintArray\b'), 'StructD'),
]

# Decompiler often emits parameter names recovered from DWARF that are
# generic English words used by Juliet helpers. These are too generic to
# strip from the function bodies (would corrupt code), but we can rename them
# in *signatures* by spotting the leading `(<type> <name>)` shape.
# Conservative: only target signatures of `void FUN_<addr>(...)` style.
_DECOMP_SIGNATURE_PARAM = re.compile(
    r'(\bFUN_[0-9a-fA-F]+\s*\(\s*)([^)]*)(\))'
)
_PARAM_NAME_BLACKLIST = {
    'line', 'data', 'dataBuffer', 'dataPtr', 'badData', 'goodData',
    'source', 'sink', 'badSource', 'goodSource', 'badSink', 'goodSink',
}


class LeakFilter:
    """Filter Juliet leaks from tool results before they reach the LLM.

    Wraps a ToolRunner instance and exposes the same ``execute()`` interface.
    Filters two endpoints:
      - ``list_strings``: drops entire lines whose content matches a leak token
      - ``decompile_function_by_address`` and ``decompile_function``: replaces
        any double-quoted string literal whose contents match a leak token
        with a single ``"[FILTERED]"`` marker, leaving the surrounding C code
        intact so data-flow analysis still works
    """

    def __init__(self, inner):
        """
        Args:
            inner: A ToolRunner (or another LeakFilter) to wrap.
        """
        self.inner = inner

    def execute(self, name, params):
        """Execute via the inner runner, then filter results if needed."""
        result, is_err = self.inner.execute(name, params)
        if is_err:
            return result, is_err

        if name == "list_strings":
            result = self._filter_strings(result)
        elif name in ("decompile_function_by_address", "decompile_function",
                      "disassemble_function"):
            result = self._filter_decompile(result)

        return result, False

    @staticmethod
    def _filter_strings(text: str) -> str:
        """Drop lines from a list_strings result that contain leak patterns."""
        if not text:
            return text

        kept = []
        dropped = 0
        for line in text.split("\n"):
            # Always keep header lines like "[Total: N] [Showing: M-K]"
            if line.startswith("[") and "]" in line:
                kept.append(line)
                continue
            if LEAK_PATTERNS.search(line):
                dropped += 1
                continue
            kept.append(line)

        if dropped > 0:
            logger.debug("LeakFilter: dropped %d strings", dropped)
            kept.append(
                f"[LeakFilter: filtered {dropped} test-suite-related strings]"
            )

        return "\n".join(kept)

    @staticmethod
    def _filter_decompile(text: str) -> str:
        """Mask leaky content in decompiled C output.

        Three passes:
          1. Replace any C-string literal whose contents match a leak token
             with the single literal ``"[FILTERED]"``. Preserves code structure.
          2. Replace Juliet-specific typedef / struct names with neutral
             ``StructA`` / ``StructB`` / etc.
          3. Rename parameter symbols inside ``FUN_<addr>(...)`` signatures
             that match the small blacklist of Juliet-helper-suggestive names
             to ``param_<n>``.
        """
        if not text:
            return text

        masked_strings = 0

        def _string_repl(m):
            nonlocal masked_strings
            content = m.group(1)
            if LEAK_PATTERNS.search(content):
                masked_strings += 1
                return '"[FILTERED]"'
            return m.group(0)

        out = _C_STRING_LITERAL.sub(_string_repl, text)

        # Pass 2: typedef rename
        for pat, repl in _DECOMP_TYPEDEF_REPLACEMENTS:
            out = pat.sub(repl, out)

        # Pass 3: signature parameter rename
        def _sig_repl(m):
            head, body, tail = m.group(1), m.group(2), m.group(3)
            if not body.strip():
                return m.group(0)
            new_params = []
            changed = False
            for idx, param in enumerate(body.split(',')):
                p = param.strip()
                if not p:
                    new_params.append(param)
                    continue
                # Last whitespace-separated token is the param name; everything
                # before it is the type. Pointers like `char *line` => name=line
                tokens = p.replace('*', '* ').split()
                if not tokens:
                    new_params.append(param)
                    continue
                name = tokens[-1].lstrip('*')
                if name in _PARAM_NAME_BLACKLIST:
                    new_name = f'param_{idx + 1}'
                    # Replace the trailing identifier in this param with new_name
                    new_param = re.sub(rf'\b{re.escape(name)}\b\s*$', new_name, param)
                    new_params.append(new_param)
                    changed = True
                else:
                    new_params.append(param)
            if not changed:
                return m.group(0)
            return head + ','.join(new_params) + tail

        out = _DECOMP_SIGNATURE_PARAM.sub(_sig_repl, out)

        if masked_strings > 0:
            logger.debug("LeakFilter: masked %d decompile string literals", masked_strings)

        return out
