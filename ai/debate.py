"""
ai/debate.py

Two-model analysis: model 1 and model 2 take turns examining the
recon data, building on or challenging each other's points, for a
fixed number of rounds. Model 1 then writes the final synthesized
report based on the full exchange.

Config for each model is read from environment variables:
  MODEL_1_PROVIDER, MODEL_1_NAME, MODEL_1_API_KEY, MODEL_1_BASE_URL
  MODEL_2_PROVIDER, MODEL_2_NAME, MODEL_2_API_KEY, MODEL_2_BASE_URL

provider is either "anthropic" or "openai_compatible" (the latter also
covers local models served through an OpenAI-style API, e.g. Ollama).
"""

import os
from dotenv import load_dotenv

from ai.llm_client import call_model

load_dotenv(override=True)

ANALYST_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst reviewing OSINT/CTI reconnaissance "
    "data (subdomains, domain reputation, resolved IPs, scan results) "
    "about a target domain. You are in a working discussion with another "
    "analyst. Build on their points, challenge them if you disagree, or "
    "add a new angle they missed. Base everything strictly on the data "
    "provided — never invent facts. Keep each turn under 120 words."
)

SYNTHESIS_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. Below is a discussion you had with "
    "a colleague about recon data for a target domain. Write a final "
    "report in clean Markdown, using this exact structure:\n\n"
    "## Summary\n"
    "2-3 sentences: what this recon run found, in plain terms.\n\n"
    "## Key Findings\n"
    "One subsection per finding (use a `###` heading per finding). For "
    "each: what was observed, any relationship to other entities worth "
    "flagging, and a **Confidence: High/Moderate/Low** line with a short "
    "reason. Keep each finding tight — a few sentences plus the "
    "confidence line, not a wall of text.\n\n"
    "## Caveats\n"
    "Short bullet list of limitations in the data or the discussion "
    "(e.g. label reliability, corpus bias, missing evidence).\n\n"
    "## Next Steps\n"
    "A numbered, prioritized list (most important first) of concrete "
    "actions an analyst should take next, ordered by what would resolve "
    "the biggest uncertainty first. 3-6 items, each one line.\n\n"
    "Base everything strictly on the data and discussion provided — "
    "never invent facts. Be direct: state what is known plainly, and "
    "flag uncertainty only where it genuinely exists, without hedging "
    "every sentence."
)


def _get_model_config(number: int) -> dict:
    prefix = f"MODEL_{number}_"
    return {
        "provider": os.getenv(prefix + "PROVIDER", ""),
        "model_name": os.getenv(prefix + "NAME", ""),
        "api_key": os.getenv(prefix + "API_KEY", ""),
        "base_url": os.getenv(prefix + "BASE_URL", ""),
    }


def _format_results(all_results: list[dict]) -> str:
    """Turn the collected recon results into a readable block for the prompt."""
    lines = []
    for r in all_results:
        line = f"- [{r.get('fonte', '?')}] {r.get('tipo', '?')}: {r.get('valore', '?')}"
        if "same_domain" in r:
            tag = "same-domain" if r["same_domain"] else "UNRELATED (merely referenced/matched, not the target's own infra)"
            line += f"  [{tag}]"
        lines.append(line)
    return "\n".join(lines) if lines else "(no data collected)"


def _build_turn_messages(transcript: list[dict], speaker: str, context: str) -> list[dict]:
    """
    Build the message history from `speaker`'s point of view: their own
    past turns are "assistant", the other model's turns are "user".
    """
    messages = [{"role": "user", "content": f"Recon data:\n{context}"}]

    if not transcript:
        messages.append({
            "role": "user",
            "content": "Propose your initial hypotheses about relationships or suspicious patterns in this data.",
        })
        return messages

    for turn in transcript:
        role = "assistant" if turn["speaker"] == speaker else "user"
        messages.append({"role": role, "content": turn["text"]})

    messages.append({
        "role": "user",
        "content": "Respond to the latest point: build on it, challenge it, or add something missed.",
    })
    return messages


def run_debate(all_results: list[dict], rounds: int = 5) -> dict:
    """
    Run the two-model exchange (default: 5 rounds = 10 total messages),
    then have model 1 synthesize a final report.

    Returns {"transcript": [...], "final_report": str}
    """
    model_1 = _get_model_config(1)
    model_2 = _get_model_config(2)

    missing = [
        name for name, cfg in [("MODEL_1", model_1), ("MODEL_2", model_2)]
        if not cfg["provider"] or not cfg["model_name"]
    ]
    if missing:
        print(f"[!] Missing config for: {', '.join(missing)}. Check your .env file.")
        return {"transcript": [], "final_report": ""}

    context = _format_results(all_results)
    transcript = []

    for round_number in range(1, rounds + 1):
        print(f"[*] Round {round_number}/{rounds} — model 1 thinking...")
        msgs_1 = _build_turn_messages(transcript, speaker="model1", context=context)
        reply_1 = call_model(
            provider=model_1["provider"], model_name=model_1["model_name"],
            system_prompt=ANALYST_SYSTEM_PROMPT, messages=msgs_1,
            api_key=model_1["api_key"], base_url=model_1["base_url"],
        )
        transcript.append({"speaker": "model1", "text": reply_1})
        print(f"    Model 1: {reply_1[:100]}...")

        print(f"[*] Round {round_number}/{rounds} — model 2 thinking...")
        msgs_2 = _build_turn_messages(transcript, speaker="model2", context=context)
        reply_2 = call_model(
            provider=model_2["provider"], model_name=model_2["model_name"],
            system_prompt=ANALYST_SYSTEM_PROMPT, messages=msgs_2,
            api_key=model_2["api_key"], base_url=model_2["base_url"],
        )
        transcript.append({"speaker": "model2", "text": reply_2})
        print(f"    Model 2: {reply_2[:100]}...")

    # Final synthesis, written by model 1
    print("[*] Model 1 writing final synthesis...")
    full_discussion = "\n\n".join(f"{t['speaker']}: {t['text']}" for t in transcript)
    synthesis_messages = [{
        "role": "user",
        "content": f"Recon data:\n{context}\n\nDiscussion:\n{full_discussion}",
    }]
    final_report = call_model(
        provider=model_1["provider"], model_name=model_1["model_name"],
        system_prompt=SYNTHESIS_SYSTEM_PROMPT, messages=synthesis_messages,
        api_key=model_1["api_key"], base_url=model_1["base_url"],
        max_tokens=1500,
    )

    return {"transcript": transcript, "final_report": final_report}
