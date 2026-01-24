# GhidraWTF (What The Function?)

Explain decompiled functions in **one click**.

`ghidrawtf.py` is a **pyGhidra script** that:
- gets the decompiled code at your current cursor
- sends the decompiled C code to an LLM backend (Gemini / OpenAI / Ollama)
- writes the result back into Ghidra as a main comment at the function entry 
  - asking to delete or append existing comments


## What you get

- **Menu entry**: `Tools -> Expl(AI)n Current Function`
- **Hotkey**: `Ctrl-Alt-W`
- **Safe re-runs**: the script tags its output and removes old tagged blocks before inserting new output
- **Multiple backends**: Gemini / OpenAI / Ollama



## Install

1. **Copy the script to your Ghidra scripts folder** (or add this repo as a Script Manager script directory):
   - In Ghidra: `Window -> Script Manager -> Script Directories`

2. **Make sure you’re running it under pyGhidra** (the script header includes `#@runtime PyGhidra`).
   - pyGhidra docs: [`Ghidra/Features/PyGhidra/src/main/py/README.md`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md)

3. **Install the provider dependency into the same Python environment that pyGhidra uses**:
  - **Gemini**: `pip install google-genai`
  - **OpenAI**: `pip install openai`
  - **Ollama**: `pip install ollama`

There's no need to install them all, the script only imports what you specify in the config.


## Configure

Open `ghidrawtf.py` and set the `CONFIG` dict at the top:

```python
CONFIG = {
    'LLMClient': 'Openai',   # 'Gemini' | 'Openai' | 'Ollama'
    'api_key':   '...',      # required for Gemini/Openai
    'host':      '',         # required for Ollama (e.g. 'http://127.0.0.1:11434')
}
```

### Provider setup

- **OpenAI**
  - Set `CONFIG['LLMClient'] = 'Openai'`
  - Set `CONFIG['api_key'] = 'YOUR_OPENAI_API_KEY'`
  - Default model in the script: `gpt-4.1-mini`

- **Gemini**
  - Set `CONFIG['LLMClient'] = 'Gemini'`
  - Set `CONFIG['api_key'] = 'YOUR_GEMINI_API_KEY'`
  - Default model in the script: `models/gemini-2.5-flash-lite`

- **Ollama (local)**
  - Set `CONFIG['LLMClient'] = 'Ollama'`
  - Set `CONFIG['host'] = 'http://127.0.0.1:11434'` (or wherever your Ollama server is)
  - Default model in the script: `qwen2.5-coder:32b`

## Use

1. Open a program in Ghidra
2. Click inside a function (Listing or Decompiler) so `currentAddress` is set
3. Run the script:
   - Menu: `Tools -> Expl(AI)n Current Function`
   - Shortcut: `Ctrl-Alt-W`
4. If a main (PLATE) comment already exists at the function entry, you’ll be prompted to **Append** or **Delete/Replace**

## Notes / Safety

- This script may send decompiled code to an external service. Make sure that’s OK for your target and policies.
- Model output can be wrong; treat it like an assistant, not a ground truth.

## References

In the following scientific paper, we found that the feature most frequently requested by our participants was a summary of the decompiled code.
This is a toy project (though it should be stable) intended for teaching and classroom use.

For a serious, multi-platform project with more features: 
[https://github.com/mahaloz/DAILA](https://github.com/mahaloz/DAILA)


```
@inproceedings{basque2026decompiling,
  title={Decompiling the Synergy: An Empirical Study of Human-LLM Teaming in Software Reverse Engineering},
  author={Zion Leonahenahe, Basque and Samuele, Doria and Ananta, Soneji and Wil, Gibbs and Adam, Doupe' and Yan, Shoshitaishvili and Eleonora, Losiouk and Ruoyu, Wang and Simone Aonzo},
  booktitle={Network and Distributed System Security (NDSS) Symposium 2026},
  year={2026},
  organization={NDSS}
}
```