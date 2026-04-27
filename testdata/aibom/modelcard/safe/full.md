---
license: apache-2.0
base_model: meta-llama/Llama-2-7b
training_data: oasst1
tags:
  - text-generation
  - chat
metrics:
  - accuracy
  - f1
---
# My Fine-Tuned Llama

A fine-tune of Llama-2-7b on the OASST-1 conversational corpus.

## License
Released under Apache-2.0 (see LICENSE file).

## Base model
Built on top of [meta-llama/Llama-2-7b](https://huggingface.co/meta-llama/Llama-2-7b).

## Training data
Trained on [OASST-1](https://huggingface.co/datasets/OpenAssistant/oasst1).

## Evaluation
On the held-out OASST-1 dev split we report:

- Accuracy: 0.92 (see Table 2 in [eval_report.md](./eval_report.md))
- F1: 0.89 (see Table 2)

Numbers were produced via the `eval/` harness; see [eval_report.md](./eval_report.md).
