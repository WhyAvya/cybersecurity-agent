"""Domain exceptions used by adapters and orchestration."""


class VulnAgentError(Exception):
    """Base class for package-specific failures."""


class ConfigurationError(VulnAgentError):
    """Configuration is invalid or cannot be loaded."""


class SecurityPolicyError(VulnAgentError):
    """A path or source file violates configured safety policy."""


class ToolError(VulnAgentError):
    """A local tool failed before returning usable output."""


class LLMError(VulnAgentError):
    """The configured LLM endpoint failed or returned invalid output."""


class SchemaParseError(VulnAgentError):
    """A model/tool response could not be parsed into the required schema."""
