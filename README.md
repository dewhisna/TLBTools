# TLBTools
Tools for manually extracting and decoding content in Microsoft COM Type Library (TLB) files

These tools were created from manually reverse-engineering Type Libraries from various COM components.  They were created to assist with doing manual modifications to existing type-libraries when the source IDL files are not available.

The primary tool of interest is the DumpTLB tool, which reads a TLB file and writes the decoded interpretation to stdout.  The ExtractTLB tool is less important and only manually searches an executable (exe, dll, ocx, etc) and writes the TLB it finds.  It's less important because generally the TLB can be extracted with the resource editors of most IDEs.

The project files are a bit outdated and are for the obsolete VC++ 6 environment.  However, you can compile the main source file from the command-line with any modern MSVC++ compiler with no special project files or compiler environment.
