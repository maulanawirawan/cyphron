# Model Recommendations for Cyphron

> Guide to choosing the right open-source LLM for running Cyphron based on your hardware.

---

## QUICK REFERENCE

| Your RAM | Recommended Model | Size on Disk | Capability | Pull Command |
|----------|-------------------|-------------|------------|--------------|
| 8 GB | `qwen2.5-coder:7b` | ~4.7 GB | Basic | `ollama pull qwen2.5-coder:7b` |
| 16 GB | `qwen2.5-coder:14b` | ~9 GB | Good | `ollama pull qwen2.5-coder:14b` |
| **32 GB** | **`qwen2.5-coder:32b`** | **~20 GB** | **Full** | **`ollama pull qwen2.5-coder:32b`** |
| 64 GB+ | `qwen2.5:72b` | ~40 GB | Expert | `ollama pull qwen2.5:72b` |

---

## DETAILED MODEL ANALYSIS

### Tier 1: 8 GB RAM — Basic Capability

**Model**: `qwen2.5-coder:7b`

| Aspect | Rating |
|---|---|
| Code review | ⭐⭐⭐☆☆ — Can identify common vulnerabilities (SQLi, XSS) |
| Secure code generation | ⭐⭐⭐☆☆ — Good for simple patterns |
| Complex reasoning | ⭐⭐☆☆☆ — Struggles with multi-step analysis |
| Instruction following | ⭐⭐⭐☆☆ — May need reminders about constraints |
| Speed | ⭐⭐⭐⭐⭐ — Very fast, even on CPU |

**Best for**: Simple code reviews, basic hardening configs, education, quick questions

**Limitations**: May miss subtle vulnerabilities. Complex threat models or architecture reviews may be incomplete. Guardrail adherence is weaker — may occasionally need correction.

---

### Tier 2: 16 GB RAM — Good Capability

**Model**: `qwen2.5-coder:14b`

| Aspect | Rating |
|---|---|
| Code review | ⭐⭐⭐⭐☆ — Identifies most vulnerability classes |
| Secure code generation | ⭐⭐⭐⭐☆ — Produces solid secure implementations |
| Complex reasoning | ⭐⭐⭐☆☆ — Handles multi-step analysis adequately |
| Instruction following | ⭐⭐⭐⭐☆ — Good adherence to constraints |
| Speed | ⭐⭐⭐⭐☆ — Fast on GPU, acceptable on CPU |

**Best for**: Most skills functional. Good for code review, tool building, hardening, education.

**Limitations**: Very complex architecture design or deep forensic analysis may lack nuance. Most users will find this tier sufficient.

---

### Tier 3: 32 GB RAM — Full Capability (RECOMMENDED)

**Model**: `qwen2.5-coder:32b`

| Aspect | Rating |
|---|---|
| Code review | ⭐⭐⭐⭐⭐ — Identifies subtle and complex vulnerabilities |
| Secure code generation | ⭐⭐⭐⭐⭐ — Production-quality secure code |
| Complex reasoning | ⭐⭐⭐⭐☆ — Strong multi-step analysis |
| Instruction following | ⭐⭐⭐⭐⭐ — Excellent constraint adherence |
| Speed | ⭐⭐⭐☆☆ — Good on GPU, slow on CPU |

**Best for**: All 15 skills fully functional. Deep code reviews, complex threat models, sophisticated tool building, architecture design.

**This is the recommended tier** for users with 32 GB+ RAM. The user mentioned wanting 30 GB+ RAM for local AI — this model fits perfectly.

**Limitations**: Slower than smaller models. On CPU-only systems, responses may take 30-60 seconds for complex queries. GPU strongly recommended.

---

### Tier 4: 64 GB+ RAM — Expert Capability

**Model**: `qwen2.5:72b` or `deepseek-coder-v2:16b`

| Aspect | Rating |
|---|---|
| Code review | ⭐⭐⭐⭐⭐ — Research-grade vulnerability analysis |
| Secure code generation | ⭐⭐⭐⭐⭐ — Expert-level secure implementations |
| Complex reasoning | ⭐⭐⭐⭐⭐ — Deep multi-step reasoning |
| Instruction following | ⭐⭐⭐⭐⭐ — Excellent constraint adherence |
| Speed | ⭐⭐☆☆☆ — Slow without high-end GPU |

**Best for**: Research-grade analysis, complex architecture design, comprehensive codebase audits.

**Note**: `qwen2.5:72b` is a general model (not coder-specific) but has stronger reasoning. `deepseek-coder-v2:16b` is a Mixture-of-Experts model that's smaller but very capable for code.

---

## ALTERNATIVE MODELS

If Qwen 2.5 Coder doesn't meet your needs, consider these alternatives:

### For Code Security
| Model | RAM Needed | Strengths | Pull Command |
|---|---|---|---|
| `deepseek-coder-v2:16b` | 32 GB | MoE architecture, strong code understanding | `ollama pull deepseek-coder-v2:16b` |
| `codellama:34b` | 32 GB | Meta's code model, good security knowledge | `ollama pull codellama:34b` |
| `starcoder2:7b` | 8 GB | Lightweight, good for simple tasks | `ollama pull starcoder2:7b` |

### For General Reasoning (non-code-specific)
| Model | RAM Needed | Strengths | Pull Command |
|---|---|---|---|
| `llama3.1:8b` | 8 GB | Strong general reasoning | `ollama pull llama3.1:8b` |
| `llama3.1:70b` | 64 GB | Expert-level reasoning | `ollama pull llama3.1:70b` |
| `mistral:7b` | 8 GB | Fast, efficient | `ollama pull mistral:7b` |
| `mixtral:8x7b` | 32 GB | MoE, strong reasoning | `ollama pull mixtral:8x7b` |

### For Indonesian Language Support
If you want Cyphron to respond well in Indonesian:
| Model | Why |
|---|---|
| `qwen2.5-coder:32b` | Qwen 2.5 has strong multilingual support including Indonesian |
| `llama3.1:70b` | Llama 3.1 has good multilingual capabilities |
| `mistral-nemo:12b` | Nemo has enhanced multilingual support |

---

## GPU CONSIDERATIONS

### NVIDIA GPU (CUDA)
- Ollama auto-detects NVIDIA GPUs
- Models load into VRAM for fast inference
- **Recommended VRAM**: Match model size (e.g., 32b model needs ~20 GB VRAM for full offload)
- **Partial offload**: If VRAM < model size, Ollama offloads what fits and uses system RAM for the rest

### Apple Silicon (M1/M2/M3/M4)
- Ollama uses Metal framework for GPU acceleration
- Unified memory means RAM = VRAM (huge advantage)
- **M1/M2/M3 with 32 GB+**: Excellent for 32b models
- **M1/M2/M3 with 16 GB**: Good for 14b models

### CPU Only
- Works but significantly slower (5-10x)
- Use smaller models (7b) for acceptable speed
- Large models (32b+) may take minutes per response

---

## CONTEXT WINDOW CONSIDERATIONS

The context window (`num_ctx` in Modelfile) determines how much text Cyphron can process at once:

| Context Size | RAM Impact | Use Case |
|---|---|---|
| 8192 | Low | Simple queries, short code snippets |
| 16384 | Medium | Medium code files, single-file review |
| 32768 | High | Large code files, multi-file review |
| 65536 | Very High | Entire codebases, long conversations |

**Recommendation**: Start with 32768 (default in Modelfile). If you run out of memory, reduce to 16384 or 8192.

---

## MODEL COMPARISON FOR SECURITY TASKS

| Task | 7b | 14b | 32b | 72b |
|---|---|---|---|---|
| Identify SQL injection | ✅ | ✅ | ✅ | ✅ |
| Identify subtle XSS contexts | ⚠️ | ✅ | ✅ | ✅ |
| Identify race conditions | ❌ | ⚠️ | ✅ | ✅ |
| Identify deserialization vulns | ⚠️ | ✅ | ✅ | ✅ |
| Identify SSRF | ⚠️ | ✅ | ✅ | ✅ |
| Generate complete patched code | ⚠️ | ✅ | ✅ | ✅ |
| Build security tools | ⚠️ | ✅ | ✅ | ✅ |
| Threat modeling (STRIDE) | ⚠️ | ✅ | ✅ | ✅ |
| Architecture design | ❌ | ⚠️ | ✅ | ✅ |
| Follow guardrails consistently | ⚠️ | ✅ | ✅ | ✅ |
| Explain attack mechanisms | ✅ | ✅ | ✅ | ✅ |
| Respond in Indonesian | ✅ | ✅ | ✅ | ✅ |

✅ = Good | ⚠️ = Acceptable but may need correction | ❌ = Struggles

---

## RECOMMENDATION FOR YOUR SETUP

Based on your mention of wanting 30 GB+ RAM for local AI:

### If you have 32 GB RAM:
```bash
# Pull the recommended model
ollama pull qwen2.5-coder:32b

# Create Cyphron
cd d:/training/.Cyphron/ollama
ollama create Cyphron -f Modelfile

# Run
ollama run Cyphron
```

### If you upgrade to 64 GB RAM later:
```bash
# Pull the expert model
ollama pull qwen2.5:72b

# Edit Modelfile to use new base model
# Change: FROM qwen2.5-coder:32b → FROM qwen2.5:72b

# Recreate
ollama create Cyphron -f Modelfile
```

---

## KEEPING MODELS UPDATED

```bash
# Check for model updates
ollama list

# Update a model (re-downloads latest version)
ollama pull qwen2.5-coder:32b

# After updating base model, recreate Cyphron
ollama create Cyphron -f Modelfile
```

Models are updated periodically with improvements. Check for updates every few months.
