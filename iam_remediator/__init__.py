"""IAM Privilege-Creep Remediator.

Analyzes granted IAM permissions against observed usage, identifies
privilege creep (granted-but-unused permissions, wildcard grants and
privilege-escalation-capable actions), and generates least-privilege
replacement policies containing only the permissions actually used.
"""

__all__ = ["loaders", "analyzer", "generator", "report"]
__version__ = "1.0.0"
