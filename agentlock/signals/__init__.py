"""Detection signals for the adaptive prompt hardening engine.

Each detector is independent: it produces signals that feed into the
HardeningEngine but shares no logic with the engine or with other
detectors.

- ``VelocityDetector``: tracks tool call frequency and topic shifts
- ``ComboDetector``: detects suspicious tool call combinations
- ``EchoDetector``: checks LLM responses for attack prompt fragments

The EchoDetector is a framework-side signal — it analyzes LLM text
responses, which the gate never sees.  Framework integrations call it
between turns and feed the resulting signals into the HardeningEngine.
"""

from agentlock.signals.combos import ComboDetector, ComboSignal
from agentlock.signals.echo import EchoDetector, EchoSignal
from agentlock.signals.prompt_scan import PromptScanConfig, PromptScanner
from agentlock.signals.velocity import VelocityDetector, VelocitySignal

__all__ = [
    "VelocityDetector",
    "VelocitySignal",
    "ComboDetector",
    "ComboSignal",
    "EchoDetector",
    "EchoSignal",
    "PromptScanner",
    "PromptScanConfig",
]
