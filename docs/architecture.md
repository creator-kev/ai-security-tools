# Prompt Injection Detection — Architecture

## Overview

The detection system uses a **hybrid multi-layer approach** combining four complementary detection strategies:

```
┌─────────────────────────────────────────────────────────────┐
│                      Input Text                             │
└─────────────────────────────┬───────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  Tokenizer    │    │  Embedding    │    │   Rules       │
│  Detector     │    │  Detector     │    │   Engine      │
│  (Fast, ~5ms) │    │  (Semantic)   │    │  (Signatures) │
└───────┬───────┘    └───────┬───────┘    └───────┬───────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                   ┌───────────────────────┐
                   │   Weighted Fusion     │
                   │   (Configurable)      │
                   └───────────┬───────────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
           ┌───────────────┐      ┌───────────────┐
           │  Score >= 0.7 │      │  Score 0.4-0.7│
           │  MALICIOUS    │      │  SUSPICIOUS   │
           └───────────────┘      └───────┬───────┘
                                          │
                                 ┌────────┴────────┐
                                 ▼                 ▼
                        ┌───────────────┐   ┌───────────────┐
                        │  LLM Judge    │   │   Review      │
                        │  (Optional)   │   │   Queue       │
                        └───────────────┘   └───────────────┘
```

## Detector Details

### 1. Tokenizer Detector (`tokenizer_detector.py`)
**Purpose**: Fast token-level anomaly detection
- **Method**: tiktoken encoding analysis
- **Signals**:
  - Rare/uncommon token frequency
  - Known injection marker phrases
  - Encoding obfuscation (base64, hex, unicode)
  - Token smuggling patterns
- **Latency**: ~5ms
- **Strengths**: Fast, no external dependencies, explainsable
- **Weaknesses**: Misses semantic attacks without known markers

### 2. Embedding Detector (`embedding_detector.py`)
**Purpose**: Semantic similarity to known injection patterns
- **Method**: sentence-transformers (all-MiniLM-L6-v2)
- **Signals**: Cosine similarity to reference injection dataset
- **Latency**: ~50-100ms (CPU), ~10ms (GPU)
- **Strengths**: Catches semantic variants, paraphrased attacks
- **Weaknesses**: Requires model download, slower

### 3. Rule Engine (`rule_engine.py`)
**Purpose**: Signature-based pattern matching
- **Method**: Compiled regex rules (20+ patterns)
- **Categories**: instruction_override, role_manipulation, data_exfiltration, bypass_attempt, encoding_obfuscation, indirect_injection, token_smuggling
- **Latency**: ~1ms
- **Strengths**: Fast, transparent, zero false positives for known patterns
- **Weaknesses**: Only catches known patterns

### 4. LLM Judge (`llm_judge.py`) — Optional
**Purpose**: Context-aware classification for edge cases
- **Method**: LLM API (OpenAI/Anthropic/local)
- **Use Case**: Borderline scores (0.4-0.7)
- **Latency**: ~500-2000ms
- **Strengths**: Best accuracy, understands context
- **Weaknesses**: Slow, cost, recursive security risk

## Fusion Strategy

```python
# Weighted combination (configurable)
final_score = (
    tokenizer_score * 0.35 +
    embedding_score * 0.35 +
    rules_score     * 0.20 +
    llm_judge_score * 0.10  # optional
)

# Classification thresholds
MALICIOUS  >= 0.70
SUSPICIOUS >= 0.42  (0.70 * 0.6)
BENIGN     < 0.42
```

## Configuration

All weights, thresholds, and detector parameters configurable via `config.yaml`:

```yaml
detector:
  weights:
    tokenizer: 0.35
    embedding: 0.35
    rules: 0.20
    llm_judge: 0.10
  thresholds:
    tokenizer: 0.72
    embedding: 0.78
    rules: 0.65
    final: 0.70
```

## Data Flow

1. **Input** → Preprocessing (truncate, normalize)
2. **Parallel Detection** → Three fast detectors run simultaneously
3. **Score Fusion** → Weighted combination
4. **Classification** → Threshold-based
5. **Optional LLM** → Edge case resolution
6. **Output** → Structured result with explanation

## Extensibility

- Add new rules: Edit `configs/injection_patterns.yaml`
- Add reference injections: Edit `configs/reference_injections.json`
- Custom tokenizer: Swap `tiktoken` for HuggingFace tokenizer
- Custom embeddings: Change model in config
- Custom rules: Add to rule engine YAML