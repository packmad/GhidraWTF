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
   - Since [Ghidra 12.0](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Configurations/Public_Release/src/global/docs/WhatsNew.md), it is the default Python scripting engine (from Jython to PyGhidra)
   - pyGhidra docs: [`Ghidra/Features/PyGhidra/src/main/py/README.md`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md)

3. **Install the provider dependency into the same Python environment that pyGhidra uses**:
  - **Gemini**: `pip install google-genai`
  - **OpenAI**: `pip install openai`
  - **Ollama**: `pip install ollama`

**There's no need to install them all**, the script only imports what you specify in the config.

E.g., Windows:
```
C:\Users\simo\AppData\Roaming\ghidra\ghidra_11.4.2_PUBLIC\venv\Scripts\python.exe -m pip install google-genai openai ollama
```

E.g., Linux:
```
/home/simo/.config/ghidra/ghidra_12.1_PUBLIC/venv/bin/python3 -m pip install google-genai openai ollama
```


## Configure

Open `ghidrawtf.py` and edit `CONFIG` (and optionally `DEFAULT_MODELS`) at the top of the file.

```python
CONFIG = {
    'LLMClient': 'Openai',   # 'Gemini' | 'Openai' | 'Ollama'
    'api_key':   '...',      # required for Gemini/Openai; leave empty for Ollama
    'host':      '',         # required for Ollama (e.g. 'http://127.0.0.1:11434')
    'model_name': '',        # optional override; empty = use DEFAULT_MODELS[LLMClient]
}

DEFAULT_MODELS = {
    'Gemini': 'models/gemini-2.5-flash-lite',
    'Openai': 'gpt-5.4-mini',
    'Ollama': 'qwen2.5-coder:32b',
}
```

| Key | Required | Description |
|-----|----------|-------------|
| `LLMClient` | yes | Backend to use: `Gemini`, `Openai`, or `Ollama` |
| `api_key` | Gemini / OpenAI | API key for the cloud provider |
| `host` | Ollama | Base URL of your Ollama server |
| `model_name` | no | Model ID passed to the backend. If empty, the script uses `DEFAULT_MODELS[LLMClient]` |

To change the default model for a provider, edit `DEFAULT_MODELS`. To override it for one run without editing defaults, set `CONFIG['model_name']` (for example `'gpt-4o'` or `'llama3.2'`).

### Provider setup

- **OpenAI**
  - `CONFIG['LLMClient'] = 'Openai'`
  - `CONFIG['api_key'] = 'YOUR_OPENAI_API_KEY'`
  - Default model: `gpt-5.4-mini` (see `DEFAULT_MODELS['Openai']`)

- **Gemini**
  - `CONFIG['LLMClient'] = 'Gemini'`
  - `CONFIG['api_key'] = 'YOUR_GEMINI_API_KEY'`
  - Default model: `models/gemini-2.5-flash-lite` (see `DEFAULT_MODELS['Gemini']`)

- **Ollama (local)**
  - `CONFIG['LLMClient'] = 'Ollama'`
  - `CONFIG['host'] = 'http://127.0.0.1:11434'` (or your Ollama URL)
  - Default model: `qwen2.5-coder:32b` (see `DEFAULT_MODELS['Ollama']`; must match a model you have pulled locally)

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
