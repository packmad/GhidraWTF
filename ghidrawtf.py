#@category Decompiler
#@menupath Tools.Expl(AI)n Current Function
#@keybinding Ctrl-Alt-W
#@toolbar
#@runtime PyGhidra

from pathlib import Path
from abc import ABC, abstractmethod
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import CodeUnit
from java.util import ArrayList

import google.generativeai as genai


CONFIG = {
    'LLMClient': 'Gemini',
    'api_key': '',
}

if CONFIG['api_key'] == '':
    script_path = Path(__file__).resolve()
    print(f'Please edit {script_path} and add your API key')
    raise SystemExit


class LLMClient(ABC):
    PROMPT: str = """
Role: You are an expert reverse engineer and malware analyst.
Context: The following code is decompiled output from Ghidra.
Task: Provide a brief, high-level summary explaining what the function does.
Focus on the function's overall purpose and behavior, not implementation details.
Emphasize any malicious or suspicious behavior if present.
Do not speculate beyond what is directly supported by the code.
"""
        
    @abstractmethod
    def summarize(self, decompiled_code: str) -> str:
        raise NotImplementedError
    

class Gemini(LLMClient):

    def __init__(self, api_key: str, model_name : str = 'models/gemini-2.5-flash-lite'):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model_name)

    def summarize(self, decompiled_code: str) -> str:
        prompt = f"{self.PROMPT}\n\nDecompiled code:\n{decompiled_code}"

        response = self.model.generate_content(
            contents=[{"role": "user", "parts": [prompt]}],
            generation_config={"temperature": 0.1},
        )
        return response.text


addr = currentAddress
if addr is None:
    print("No currentAddress. Click in Listing or Decompiler to set a location.")
    raise SystemExit

func = getFunctionContaining(addr)
if func is None:
    print(f"No function containing address {addr}.")
    raise SystemExit

di = DecompInterface()
di.openProgram(currentProgram)

res = di.decompileFunction(func, 32, monitor)
if not res.decompileCompleted():
    print("Decompilation failed:", res.getErrorMessage())
    raise SystemExit

df = res.getDecompiledFunction()
if df is None:
    print("No DecompiledFunction returned.")
    raise SystemExit

llm_client: LLMClient = globals()[CONFIG['LLMClient']](CONFIG['api_key'])
summary = llm_client.summarize(df.getC())
if not summary:
    print("Empty summary returned!?!?")
    raise SystemExit

listing = currentProgram.getListing()
entry = func.getEntryPoint()
cu = listing.getCodeUnitAt(entry)

existing = ""
if cu is not None:
    existing = cu.getComment(CodeUnit.PLATE_COMMENT) or ""

# Prepare the comment text to write
# (Keep the summary at the very top in both cases.)
if existing.strip():
    # Two-button choice via askChoice (Append/Delete)
    opts = ArrayList()
    opts.add("Append")
    opts.add("Delete")
    # default MUST be one of the objects in opts (opts.get(0) here)
    choice = askChoice("Existing Comment Found", 
              "A plate comment already exists at the top of this function.\nWhat do you want to do?", 
              opts, opts.get(0))

    if choice == "Append":
        new_comment = summary + "\n\n" + existing.strip()
    else:  # "Delete"
        new_comment = summary
else:
    new_comment = summary

# Apply change under a transaction
tid = currentProgram.startTransaction("Expl(AI)n: Add summary plate comment")
try:
    # Ensure we have a code unit to attach the plate comment to
    if cu is None:
        cu = listing.getCodeUnitAt(entry)
    if cu is None:
        # Fallback: set the comment directly on the entry point address if needed
        listing.setComment(entry, CodeUnit.PLATE_COMMENT, new_comment)
    else:
        cu.setComment(CodeUnit.PLATE_COMMENT, new_comment)
finally:
    currentProgram.endTransaction(tid, True)
