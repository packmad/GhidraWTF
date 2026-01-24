#@category Decompiler
#@menupath Tools.Expl(AI)n Current Function
#@keybinding Ctrl-Alt-W
#@toolbar
#@runtime PyGhidra
import re
from pathlib import Path
from abc import ABC, abstractmethod
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import CodeUnit
from java.util import ArrayList


CONFIG = {
    'LLMClient': '',
    'api_key': '',
    'host': '',
}

if CONFIG['LLMClient'] not in {'Gemini', 'Ollama', 'Openai'}:
    print(f'Unsupported LLMClient: {CONFIG['LLMClient']}')
    raise SystemExit

if CONFIG['api_key'] == '' and CONFIG['LLMClient'] != 'Ollama':
    script_path = Path(__file__).resolve()
    print(f'Please edit {script_path} and add your API key')
    raise SystemExit


class LLMClient(ABC):
    PROMPT: str =  """
Role: You are an expert reverse engineer in analyzing decompiled binaries.
Context: You are given the output of Ghidra's decompiler for a single function.
Task: Produce a concise, high-level summary of the function's purpose and observable behavior.
Guidelines:
- Describe what the function does, not how it is implemented.
- Base your explanation strictly on evidence present in the decompiled code.
- Avoid speculation, assumptions about intent, or references to missing context.
Decompiled function:\n
"""
    TAG_BEGIN = ">>>BEGIN-AI-GENERATED-CONTENT>>>"
    TAG_END   = "<<END-AI-GENERATED-CONTENT<<<"
    TAG_BLOCK = re.compile(re.escape(TAG_BEGIN) + r".*?" + re.escape(TAG_END), flags=re.DOTALL)
    DEC_WARNING = '\n/* WARNING: Type propagation algorithm not settling */\r\n'

    def append_tag(self, txt: str) -> str:
        return f"{self.TAG_BEGIN}\n{txt}\n{self.TAG_END}\n"
    
    def summarize(self, decompiled_code: str) -> str:
        prompt = f"{self.PROMPT}{self.TAG_BLOCK.sub('', decompiled_code.replace(self.DEC_WARNING, ''))}"
        print(f'!DEBUG {prompt=}')
        answer = self.append_tag(self._summarize_impl(prompt))
        print(f'!DEBUG {answer=}')
        return answer

    @abstractmethod
    def _summarize_impl(self, prompt: str) -> str:
        raise NotImplementedError


match CONFIG['LLMClient']:
    case 'Gemini':
        import google.generativeai as genai  # pip install google-genai

        class Gemini(LLMClient):
            
            def __init__(self, api_key: str, model_name : str = 'models/gemini-2.5-flash-lite'):
                genai.configure(api_key=api_key)
                self.model = genai.GenerativeModel(model_name)

            def _summarize_impl(self, prompt: str) -> str:
                response = self.model.generate_content(
                    contents=[{"role": "user", "parts": [prompt]}],
                    generation_config={"temperature": 0.1},
                )
                return response.text
    case 'Openai':
        from openai import OpenAI  # pip install openai 

        class Openai(LLMClient):
            
            def __init__(self, api_key: str, model_name : str = "gpt-4.1-mini"):
                self.openai_client = OpenAI(api_key=api_key)
                self.model_name = model_name

            def _summarize_impl(self, prompt: str) -> str:
                response = self.openai_client.responses.create(
                    model=self.model_name, input=prompt, temperature=0.1)
                return response.output_text
                
    case 'Ollama':
        if CONFIG['host'] == '':
            print('You must specify the host for Ollama')
            raise SystemExit

        from ollama import Client  # pip install ollama
        
        class Ollama(LLMClient):
            
            def __init__(self, api_key: str, model_name : str = 'qwen2.5-coder:32b'):
                self.model = Client(host=CONFIG['host'])
                self.model_name = model_name
            
            def _summarize_impl(self, prompt: str) -> str:
                user_message = {'role': 'user', 'content': prompt}
                params = {'temperature': 0.1}
                response = self.model.chat(model=self.model_name, options=params, messages=[user_message])
                return response['message']['content']

    case _:
        print(f'Unsupported LLMClient: {CONFIG['LLMClient']}')
        raise SystemExit
    

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


if existing.strip():
    opts = ArrayList()
    opts.add("Append")
    opts.add("Delete")
    choice = askChoice("Existing Comment Found", 
              "A plate comment already exists at the top of this function.\nWhat do you want to do?", 
              opts, opts.get(0))

    if choice == "Append":
        new_comment = summary + "\n\n" + existing.strip()
    else:  # "Delete"
        new_comment = summary
else:
    new_comment = summary

tid = currentProgram.startTransaction("Expl(AI)n: Add summary plate comment")
try:
    if cu is None:
        cu = listing.getCodeUnitAt(entry)
    if cu is None:
        # Fallback: set the comment directly on the entry point address if needed
        listing.setComment(entry, CodeUnit.PLATE_COMMENT, new_comment)
    else:
        cu.setComment(CodeUnit.PLATE_COMMENT, new_comment)
finally:
    currentProgram.endTransaction(tid, True)
