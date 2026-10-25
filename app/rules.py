"""Stage 1: deterministic rules (regex, structural checks, length).

Severity:
  HIGH   -> block immediately, skip the semantic stage.
  MEDIUM -> suspicious; recorded, and the semantic stage uses a lower threshold.

Rules run on normalized, lowercased text (see normalize.py). Patterns use bounded
gaps ({0,N}?) instead of .* so they stay fast on hostile input.
Rule of thumb: only make a rule HIGH if a benign user would almost never type it.
"""

import re
from dataclasses import dataclass
from enum import Enum

from .normalize import has_invisible_chars


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: Severity
    pattern: re.Pattern


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    category: str
    severity: Severity
    matched: str


def _r(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


H, M = Severity.HIGH, Severity.MEDIUM

RULES: list[Rule] = [
    # --- Instruction override ---
    Rule("override.ignore_previous", "instruction_override", H, _r(
        r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}?"
        r"\b(previous|prior|above|earlier|preceding|all|any|your|the|system|these)\b.{0,25}?"
        r"\b(instructions?|rules|prompts?|directives?|guidelines|guardrails|constraints|programming)\b"
    )),
    Rule("override.new_instructions", "instruction_override", M, _r(
        r"\b(new|updated|real|actual|true)\s+(system\s+)?(instructions?|rules|directives?)\s*(are|:|follow)"
    )),

    # --- System prompt extraction ---
    Rule("extract.system_prompt", "system_prompt_extraction", H, _r(
        r"\b(reveal|show|print|display|repeat|output|leak|dump|recite|tell me|give me|share)\b.{0,30}?"
        r"\b(your|the|this)\s+(full\s+|entire\s+|exact\s+)?(system prompt|system message|initial (instructions|prompt)|"
        r"hidden (instructions|prompt)|original (instructions|prompt)|developer (message|instructions)|instructions you were given)\b"
    )),
    Rule("extract.what_is_your_prompt", "system_prompt_extraction", H, _r(
        r"\bwhat (is|are|was|were)\s+your\s+(exact\s+|full\s+|original\s+|initial\s+|hidden\s+)?"
        r"(system prompt|system message|instructions|prompt)\b"
    )),
    Rule("extract.verbatim_above", "system_prompt_extraction", H, _r(
        r"\b(repeat|print|output|copy)\b.{0,30}?\b(everything|all( the)? text|the words?)\b.{0,20}?\b(above|before this|so far)\b"
    )),

    # --- Persona jailbreaks ---
    Rule("persona.known_names", "persona_jailbreak", H, _r(
        r"\b(you are|you're|act as|become|pretend to be|enable|activate)\s+(now\s+)?(dan|stan|dude)\b"
        r"|\bdo anything now\b"
        r"|\b(dan|jailbreak|jailbroken)\s+mode\b"
    )),
    Rule("persona.mode_switch", "persona_jailbreak", M, _r(
        r"\b(developer|god|unrestricted|unfiltered|evil)\s+mode\b"
    )),
    Rule("persona.unrestricted", "persona_jailbreak", H, _r(
        r"\b(you are now|from now on,? you|act as|pretend (to be|you are|you're)|roleplay as|become)\b.{0,60}?"
        r"\b(unrestricted|unfiltered|uncensored|no (rules|limits|restrictions|filters|guidelines|ethics)|"
        r"without (any )?(rules|limits|restrictions|filters|guidelines|ethics)|free from (all )?(rules|restrictions))\b"
    )),
    Rule("persona.no_refusal", "persona_jailbreak", M, _r(
        r"\b(never|don'?t|do not|cannot|can'?t|must not)\s+(refuse|decline|say no)\b"
    )),

    # --- VM / simulation framing ---
    Rule("framing.vm_terminal", "vm_framing", M, _r(
        r"\b(act as|pretend to be|simulate|emulate|you are)\b.{0,30}?\b(linux terminal|virtual machine|vm|shell|bash terminal|"
        r"python interpreter|unrestricted ai|another ai)\b"
    )),
    Rule("framing.hypothetical_bypass", "vm_framing", M, _r(
        r"\b(hypothetical(ly)?|in a fictional world|for a story|in this simulation|imagine a world)\b.{0,80}?"
        r"\b(no (rules|laws|restrictions|filters)|anything is allowed|no consequences)\b"
    )),

    # --- Fake chat-template / role delimiters ---
    Rule("structure.fake_delimiters", "fake_delimiter", H, _r(
        r"(<\|?\s*(im_start|im_end|system|endoftext|eot_id|start_header_id)\s*\|?>|\[/?inst\]|<<\s*/?sys\s*>>)"
    )),
    Rule("structure.fake_role_header", "fake_delimiter", M, _r(
        r"(^|\n)\s*(#{2,}|\*\*|\[)\s*(system|admin|developer|root)\s*(message|prompt|override|instructions?)?\s*(\]|\*\*|:)"
    )),

    # --- Indirect injection (instructions aimed at the model, hidden in content) ---
    Rule("indirect.addressed_to_ai", "indirect_injection", M, _r(
        r"\b(ai|assistant|language model|llm|chatbot)\b.{0,20}?\b(reading|processing|summari[sz]ing|analy[sz]ing) this\b"
    )),
    Rule("indirect.exfil_link", "data_exfiltration", H, _r(
        r"!\[[^\]]{0,100}\]\(\s*https?://[^)\s]{1,200}[?&][^)\s=]{0,50}=\s*[{<\[]?\s*"
        r"(data|secret|password|token|key|conversation|history|prompt|user)"
    )),
]

MAX_PROMPT_CHARS = 20_000   # hard cap -> block
LONG_PROMPT_CHARS = 6_000   # suspicious -> medium

_RULE_IDS_NO_SMUGGLING = ("structure.", "anomaly.")


def run_rules(raw: str, variants: list[str]) -> list[RuleHit]:
    """Run all rules over every text variant. variants[0] is the canonical text."""
    hits: list[RuleHit] = []

    # Structural checks on the raw text, before normalization strips the evidence.
    if has_invisible_chars(raw):
        hits.append(RuleHit("structure.invisible_chars", "obfuscation", M, "<zero-width/tag chars>"))
    if len(raw) > MAX_PROMPT_CHARS:
        hits.append(RuleHit("anomaly.too_long", "length_anomaly", H, f"{len(raw)} chars"))
    elif len(raw) > LONG_PROMPT_CHARS:
        hits.append(RuleHit("anomaly.long", "length_anomaly", M, f"{len(raw)} chars"))

    plain_ids: set[str] = set()
    seen: set[str] = set()
    for i, text in enumerate(variants):
        for rule in RULES:
            if rule.id in seen:
                continue
            m = rule.pattern.search(text)
            if m:
                seen.add(rule.id)
                if i == 0:
                    plain_ids.add(rule.id)
                hits.append(RuleHit(rule.id, rule.category, rule.severity, m.group(0)[:120]))

    # Something only matched after decoding / de-leeting: the user is hiding it on purpose.
    smuggled = seen - plain_ids
    if any(not rid.startswith(_RULE_IDS_NO_SMUGGLING) for rid in smuggled):
        hits.append(RuleHit("obfuscation.encoded_payload", "obfuscation", H, "<matched only after decoding>"))

    return hits
