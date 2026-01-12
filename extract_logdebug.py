#!/usr/bin/env python3
"""
Extract all LogDebug() macro invocations from Bitcoin Core source code.

This script uses libclang to parse C++ source files and extract:
- Format string template
- All arguments with their types and source code names
"""

import sys
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import clang.cindex
except ImportError:
    print("Error: clang package not found. Install with: pip install clang")
    sys.exit(1)

SKIP_PATHS = [
    "bitcoin/src/test/",
    "bitcoin/src/bench/",
    "bitcoin/src/wallet/",
    "bitcoin/src/qt/",
    "bitcoin/contrib/",
];


class LogDebugExtractor:
    def __init__(self, source_dir: Path):
        self.source_dir = Path(source_dir)
        self.results: List[Dict[str, Any]] = []
    
    def get_source_files(self) -> List[Path]:
        """Find all C++ source files in the source directory."""
        cpp_files = []
        for ext in ['*.cpp', '*.cc', '*.cxx', '*.h']:
            cpp_files.extend(self.source_dir.rglob(ext))
        return sorted(cpp_files)
    
    def get_format_string(self, cursor) -> Optional[str]:
        """Extract the format string from a LogDebug call."""
        # LogDebug(category, format_string, ...)
        # We need to find the second argument (format string)
        children = list(cursor.get_children())
        if len(children) < 2:
            return None
        
        # Skip the first child (category), get the second (format string)
        format_cursor = children[1]
        
        # Get the token spelling
        tokens = list(format_cursor.get_tokens())
        if not tokens:
            return None
        
        # Try to extract string literal
        for token in tokens:
            if token.kind == clang.cindex.TokenKind.LITERAL:
                spelling = token.spelling
                # Remove quotes and handle escape sequences
                if spelling.startswith('"') and spelling.endswith('"'):
                    return spelling[1:-1]  # Remove quotes
                elif spelling.startswith('R"'):
                    # Raw string literal
                    match = re.match(r'R"([^(]*)\(' + r'(.*)' + r'\)\1"', spelling)
                    if match:
                        return match.group(2)
        
        # Fallback: get the spelling directly
        return format_cursor.spelling
    
    def get_argument_info(self, cursor) -> Dict[str, Any]:
        """Extract type and name information from an argument cursor."""
        info = {
            'type': cursor.type.spelling if cursor.type else 'unknown',
            'name': cursor.spelling or cursor.displayname,
            'source': self.get_source_code(cursor),
        }
        return info
    
    def get_source_code(self, cursor) -> str:
        """Get the source code representation of a cursor."""
        extent = cursor.extent
        if extent.start.file:
            try:
                with open(extent.start.file.name, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    start_line = extent.start.line - 1
                    end_line = extent.end.line
                    if start_line < len(lines) and end_line <= len(lines):
                        code_lines = lines[start_line:end_line]
                        if code_lines:
                            # Adjust column for first and last line
                            first_line = code_lines[0]
                            last_line = code_lines[-1]
                            if len(code_lines) == 1:
                                return first_line[extent.start.column-1:extent.end.column-1].strip()
                            else:
                                first_line = first_line[extent.start.column-1:]
                                last_line = last_line[:extent.end.column-1]
                                code_lines[0] = first_line
                                code_lines[-1] = last_line
                                return ''.join(code_lines).strip()
            except Exception as e:
                return f"<error reading source: {e}>"
        return cursor.spelling or cursor.displayname
    
    def extract_logdebug_calls(self, translation_unit, file_path: Path) -> List[Dict[str, Any]]:
        """Extract all LogDebug calls from a translation unit."""
        calls = []
        
        # First, try to find macro invocations
        # Read the source file to find LogDebug calls
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_lines = f.readlines()
        except Exception:
            return calls
        
        # Find all LogDebug invocations using regex (as fallback)
        for line_num, line in enumerate(source_lines, 1):
            # Look for LogDebug( pattern
            matches = re.finditer(r'LogDebug\s*\(', line)
            for match in matches:
                # Try to parse the arguments
                start_pos = match.end() - 1  # Position of opening paren
                call_info = self.parse_logdebug_call(
                    source_lines, line_num - 1, start_pos, file_path
                )
                if call_info:
                    calls.append(call_info)
        
        # Also try AST-based extraction for expanded macros
        def visit_node(cursor):
            # Check for macro expansion
            if cursor.kind == clang.cindex.CursorKind.MACRO_INSTANTIATION:
                if cursor.spelling == 'LogDebug':
                    # This is a macro instantiation
                    call_info = self.extract_from_macro(cursor, file_path)
                    if call_info:
                        calls.append(call_info)
            
            # Check if this is a call expression (for expanded macros)
            if cursor.kind == clang.cindex.CursorKind.CALL_EXPR:
                # Check if it's calling something that looks like LogDebug
                if 'LogDebug' in cursor.displayname or 'LogDebug' in cursor.spelling:
                    call_info = self.extract_from_call_expr(cursor, file_path)
                    if call_info:
                        calls.append(call_info)
            
            # Recursively visit children
            for child in cursor.get_children():
                visit_node(child)
        
        visit_node(translation_unit.cursor)
        return calls
    
    def parse_logdebug_call(self, source_lines: List[str], start_line: int, 
                           start_col: int, file_path: Path) -> Optional[Dict[str, Any]]:
        """Parse a LogDebug call from source code using text parsing."""
        # Find the matching closing parenthesis
        paren_count = 0
        pos = start_col
        end_pos = None
        end_line = None
        in_string = False
        string_char = None
        
        # Find the end of the call by tracking parentheses and strings
        for i in range(start_line, len(source_lines)):
            current_line = source_lines[i]
            start_idx = pos if i == start_line else 0
            
            for j in range(start_idx, len(current_line)):
                char = current_line[j]
                
                if not in_string:
                    if char in ['"', "'"]:
                        in_string = True
                        string_char = char
                    elif char == '(':
                        paren_count += 1
                    elif char == ')':
                        paren_count -= 1
                        if paren_count == 0:
                            end_pos = j + 1
                            end_line = i
                            break
                else:
                    if char == string_char and (j == 0 or current_line[j-1] != '\\'):
                        in_string = False
                        string_char = None
            
            if paren_count == 0 and end_pos is not None:
                break
        
        if end_pos is None or end_line is None:
            return None
        
        # Extract the full call
        if start_line == end_line:
            call_text = source_lines[start_line][start_col:end_pos]
        else:
            call_text = (source_lines[start_line][start_col:] + 
                        ''.join(source_lines[start_line+1:end_line]) + 
                        source_lines[end_line][:end_pos])
        
        # Parse arguments: LogDebug(category, format, ...)
        # Remove "LogDebug(" prefix
        args_text = call_text[8:].rstrip(')').strip()
        
        # Parse arguments (handle nested parentheses and strings)
        args = self.parse_arguments(args_text)
        
        if len(args) < 2:
            return None
        
        category = args[0].strip()
        format_string = args[1].strip()
        
        # Extract format string (remove quotes)
        format_match = re.match(r'^["\'](.*)["\']$', format_string, re.DOTALL)
        if format_match:
            format_string = format_match.group(1)
        else:
            # Try raw string literal
            raw_match = re.match(r'^R"([^(]*)\(' + r'(.*)' + r'\)\1"$', format_string, re.DOTALL)
            if raw_match:
                format_string = raw_match.group(2)
        
        # Extract remaining arguments
        arg_list = []
        for arg_text in args[2:]:
            arg_info = {
                'source': arg_text.strip(),
                'type': 'unknown',  # Would need AST to determine
                'name': self.extract_variable_name(arg_text.strip()),
            }
            arg_list.append(arg_info)
        
        return {
            'file': str(file_path),
            'line': start_line + 1,
            'column': start_col + 1,
            'category': category,
            'format_string': format_string,
            'arguments': arg_list,
            'source_code': call_text.strip(),
        }
    
    def parse_arguments(self, args_text: str) -> List[str]:
        """Parse comma-separated arguments, handling nested parentheses and strings."""
        args = []
        current_arg = []
        paren_count = 0
        in_string = False
        string_char = None
        i = 0
        
        while i < len(args_text):
            char = args_text[i]
            
            if not in_string:
                if char in ['"', "'"]:
                    in_string = True
                    string_char = char
                    current_arg.append(char)
                elif char == '(':
                    paren_count += 1
                    current_arg.append(char)
                elif char == ')':
                    paren_count -= 1
                    current_arg.append(char)
                elif char == ',' and paren_count == 0:
                    args.append(''.join(current_arg))
                    current_arg = []
                else:
                    current_arg.append(char)
            else:
                current_arg.append(char)
                # Check for end of string (handle escaped quotes)
                if char == string_char:
                    # Check if it's escaped (look back, but handle start of string)
                    if i == 0 or args_text[i-1] != '\\':
                        in_string = False
                        string_char = None
                    elif i > 0 and args_text[i-1] == '\\':
                        # Check if the backslash itself is escaped
                        if i > 1 and args_text[i-2] == '\\':
                            in_string = False
                            string_char = None
            
            i += 1
        
        if current_arg:
            args.append(''.join(current_arg))
        
        return args
    
    def extract_variable_name(self, expr: str) -> str:
        """Try to extract a variable/function name from an expression."""
        # Remove whitespace
        expr = expr.strip()
        
        # If it's a simple identifier
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', expr):
            return expr
        
        # If it's a method call like obj.method()
        match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)', expr)
        if match:
            return match.group(1)
        
        # If it's a function call
        match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\(', expr)
        if match:
            return match.group(1)
        
        return expr
    
    def extract_from_macro(self, cursor, file_path: Path) -> Optional[Dict[str, Any]]:
        """Extract information from a macro instantiation cursor."""
        # Get the source location
        location = cursor.location
        if not location.file:
            return None
        
        # Read source around this location
        try:
            with open(location.file.name, 'r', encoding='utf-8', errors='ignore') as f:
                source_lines = f.readlines()
        except Exception:
            return None
        
        if location.line > len(source_lines):
            return None
        
        line = source_lines[location.line - 1]
        # Find LogDebug( in this line
        match = re.search(r'LogDebug\s*\(', line)
        if match:
            return self.parse_logdebug_call(
                source_lines, location.line - 1, match.start(), Path(location.file.name)
            )
        
        return None
    
    def extract_from_call_expr(self, cursor, file_path: Path) -> Optional[Dict[str, Any]]:
        """Extract information from a call expression cursor."""
        children = list(cursor.get_children())
        if len(children) < 2:
            return None
        
        category_cursor = children[0]
        format_cursor = children[1]
        args_cursors = children[2:]
        
        # Extract format string
        format_string = self.get_format_string(cursor)
        if format_string is None:
            format_string = self.get_source_code(format_cursor)
            # Try to extract string literal
            match = re.search(r'["\']([^"\']*)["\']', format_string)
            if match:
                format_string = match.group(1)
        
        # Extract category
        category = self.get_source_code(category_cursor)
        
        # Extract arguments
        args = []
        for arg_cursor in args_cursors:
            arg_info = self.get_argument_info(arg_cursor)
            args.append(arg_info)
        
        return {
            'file': str(cursor.location.file.name) if cursor.location.file else str(file_path),
            'line': cursor.location.line,
            'column': cursor.location.column,
            'category': category,
            'format_string': format_string,
            'arguments': args,
            'source_code': self.get_source_code(cursor),
        }
    
    def process_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Process a single C++ source file."""
        print(f"Processing {file_path}...", file=sys.stderr)
        
        index = clang.cindex.Index.create()
        
        try:

            cdb = cindex.CompilationDatabase.fromDirectory(
                str(self.source_dir.parent / "build")
            )

            commands = cdb.getCompileCommands(str(file_path))
            if not commands:
                print(f"  No compile command for {file_path}", file=sys.stderr)
                return []

            cmd = commands[0]

            # Drop the compiler executable (clang++ / g++)
            args = list(cmd.arguments)[1:]

            translation_unit = index.parse(
                str(file_path),
                args=args,
                options=clang.cindex.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES | clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
                unsaved_files=None,
            )         
            # Check for errors
            if translation_unit.diagnostics:
                # Filter out common non-critical errors
                critical_errors = [
                    d for d in translation_unit.diagnostics
                    if d.severity >= clang.cindex.Diagnostic.Error
                ]
                if critical_errors:
                    print(f"  Warning: {len(critical_errors)} errors parsing {file_path}", file=sys.stderr)
                    for error in critical_errors:
                        print(f"    {error.spelling}", file=sys.stderr)
                        print(f"    {error.location.file.name}:{error.location.line}:{error.location.column}", file=sys.stderr)
                        #print(f"    {error.source_location.file.name}:{error.source_location.line}:{error.source_location.column}", file=sys.stderr)

            return self.extract_logdebug_calls(translation_unit, file_path)
        except Exception as e:
            print(f"  Error processing {file_path}: {e}", file=sys.stderr)
            return []
    
    def run(self):
        """Run the extraction on relevant source files."""
        source_files = self.get_source_files()
        print(f"Found {len(source_files)} source files", file=sys.stderr)
        
        for file_path in source_files:
            if any(str(file_path).startswith(skip_path) for skip_path in SKIP_PATHS):
                print(f"Skipping {file_path}..", file=sys.stderr)
                continue
            
            calls = self.process_file(file_path)
            self.results.extend(calls)
        
        return self.results


def main():
    if len(sys.argv) < 2:
        print("Usage: extract_logdebug.py <source_directory> [output_file.json]")
        sys.exit(1)
    
    source_dir = Path(sys.argv[1])
    if not source_dir.exists():
        print(f"Error: Source directory {source_dir} does not exist")
        sys.exit(1)
    
    extractor = LogDebugExtractor(source_dir)
    results = extractor.run()
    
    # Output results
    if len(sys.argv) > 2:
        output_file = Path(sys.argv[2])
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nExtracted {len(results)} LogDebug calls to {output_file}", file=sys.stderr)
    else:
        print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()

