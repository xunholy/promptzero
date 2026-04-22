# Local domain fine-tune — operator guide

PromptZero ships with every grounding layer an operator needs without
a custom model: per-tool cheat sheets (`internal/toolctx`), BM25
retrieval over the docs corpus (`internal/rag`), chain-of-verification
on parametric builds (`internal/agent/verify_build.go`), and prospective
reflection on critical tools (`internal/agent/prospective.go`).

When those aren't enough — typically because your targets, protocols,
or naming conventions diverge from what Anthropic's base models saw
in training — a local domain fine-tune is the next lever. This guide
walks through the full path from audit log to deployed checkpoint.

The session that produced this doc **did not** train a model. That
requires GPU time outside the scope of an interactive session. The
batch-G deliverable is the runbook itself so operators can execute it
on their own hardware.

---

## 1. Collect a dataset

Every tool call PromptZero makes is recorded in the audit log. After
a representative run of sessions (goal: at least a few hundred high-
quality calls across the tools you care about), export:

```sh
/export training-set ~/promptzero-training.jsonl
```

Or with filters:

```sh
# Chat-format, only successful calls, only warning + critical risk:
/export training-set ~/ft-critical.jsonl --format=chat --success-only --min-level=warning
```

Every row carries:

- tool name (label)
- tool input (parameters the base model chose)
- tool output (what the hardware / downstream service returned)
- risk level, ATT&CK technique IDs, success/failure flag

**Rule of thumb for dataset size:** LoRA fine-tunes start showing
meaningful benefit around 500 well-labelled examples; 2000+ is where
the base model's behaviour visibly shifts without needing test-time
grounding. Below 500, stay on the RAG path — fine-tuning small corpora
risks overfit.

**Data hygiene:** strip sessions where the operator knows the base
model made the wrong choice. Keep failed calls only if the failure
was the hardware's fault, not the model's reasoning. The export
respects `--success-only` for that.

---

## 2. Pick a training framework

PromptZero doesn't prescribe one — the JSONL export shape works with
every mainstream framework. Three good defaults:

| Framework | When to pick it | Notes |
| --- | --- | --- |
| [Axolotl](https://github.com/OpenAccess-AI-Collective/axolotl) | Single-GPU LoRA/QLoRA, rapid iteration | YAML-driven; handles 4-bit quant out of the box |
| [Hugging Face TRL](https://huggingface.co/docs/trl) | Multi-GPU, full PEFT toolkit | Best when you want custom loss (DPO, ORPO, KTO) |
| [Unsloth](https://github.com/unslothai/unsloth) | Fastest single-GPU path | 2x training speed vs Axolotl; smaller ecosystem |

Base model choice: start with a 7B-to-13B open model whose native
tool-use is reasonable (Llama 3.1 8B Instruct, Mistral 7B, Qwen 2.5
7B Instruct). Your fine-tune adds PromptZero's tool-use conventions
on top — you don't need to teach it the basics.

---

## 3. Hardware requirements

Training on the FormatChat export with a 7B-8B base model:

| Approach | GPU | VRAM | Training time (1000 rows, 3 epochs) |
| --- | --- | --- | --- |
| QLoRA (4-bit) | RTX 3090 / 4090 | 24 GB | 1-2 hours |
| QLoRA | RTX A6000 | 48 GB | 30-60 min |
| LoRA (16-bit) | A100 40GB | 40 GB | 15-30 min |
| Full fine-tune | 2x A100 80GB | 160 GB | 4-8 hours |

Rented GPU services (Modal, RunPod, Lambda, Vast) are the practical
path for operators without local GPUs. A single training run costs
USD 2-10 depending on the rig.

---

## 4. Training recipe (Axolotl / QLoRA)

A canonical Axolotl config for PromptZero's chat-format export,
saved as `promptzero-lora.yml`:

```yaml
base_model: meta-llama/Llama-3.1-8B-Instruct
model_type: LlamaForCausalLM
tokenizer_type: AutoTokenizer

load_in_4bit: true
strict: false

datasets:
  - path: ./promptzero-training.jsonl
    type: chat_template
    chat_template: llama3
    field_messages: messages

dataset_prepared_path: ./prepared
val_set_size: 0.05
output_dir: ./out

sequence_len: 2048
sample_packing: true

adapter: qlora
lora_model_dir:
lora_r: 16
lora_alpha: 32
lora_dropout: 0.05
lora_target_modules:
  - q_proj
  - k_proj
  - v_proj
  - o_proj

gradient_accumulation_steps: 4
micro_batch_size: 2
num_epochs: 3
optimizer: paged_adamw_32bit
lr_scheduler: cosine
learning_rate: 0.0002

bf16: auto
fp16: false

logging_steps: 10
save_strategy: epoch
save_total_limit: 3
warmup_ratio: 0.1
```

Launch:

```sh
pip install axolotl[flash-attn]
accelerate launch -m axolotl.cli.train promptzero-lora.yml
```

---

## 5. Evaluate the checkpoint

Re-run PromptZero's golden eval harness against the fine-tuned model
before shipping it:

```sh
task eval
```

The default suite covers the critical agent layers (handoff,
snapshots, ATT&CK constraints, detectors, tool errors, campaigns,
confidence, prompt-injection quarantine, placeholder detection).
A fine-tune that regresses any of those isn't ready.

For task-level benchmarks, tag a subset of audit entries as holdout
before exporting the training set, then replay the fine-tuned model
against them and diff tool-choice accuracy.

---

## 6. Serve the checkpoint

Two viable patterns:

- **OpenAI-compatible endpoint (recommended)**: serve via vLLM or
  SGLang, then point PromptZero's `PROMPTZERO_API_BASE` at the
  local endpoint. Zero code changes needed.

  ```sh
  vllm serve ./out --port 8000
  export PROMPTZERO_API_BASE=http://localhost:8000/v1
  export PROMPTZERO_MODEL=./out
  ```

- **Provider plugin**: implement `internal/provider.Provider` to
  route calls to your inference backend (Ollama, llama.cpp, Together,
  Anyscale). This is more work but lets you stack multiple backends
  (e.g. Haiku for verify, your fine-tune for tool-use).

The fine-tune does NOT replace the safety layers — verify_build,
prospective reflection, quarantine, and confidence scoring still
run on top. A fine-tuned checkpoint is faster grounding, not a
weaker safety story.

---

## 7. Iterate

- Re-export every few weeks as your session history grows.
- Keep datasets separate per persona / operator team if you're
  training models for different use cases.
- When the hit rate on `docs_search` drops (check via `/audit find
  tool=docs_search`), that's a signal the model has internalised
  the retrieval layer — a good proxy for fine-tune quality.

Future PromptZero work (not in this batch):
- `task ft:train` wrapper around Axolotl for single-command training
- `task ft:serve` wrapper around vLLM
- `task ft:eval` that auto-diffs fine-tuned vs base model on the
  golden suite
