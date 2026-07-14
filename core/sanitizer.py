import re
from typing import Optional, Tuple
from core.logger import logger

class TargetSanitizer:
    DOM_REGEX = re.compile(
        r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])'
        r'(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))*$'
    )
    IP_REGEX = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )

    @classmethod
    def clean_target(cls, raw_input: str) -> Tuple[Optional[str], str]:
        try:
            if not raw_input:
                return None, "INVALID"
            cleaned = raw_input.strip().lower()
            cleaned = re.sub(r'^https?://', '', cleaned)
            cleaned = cleaned.split('/')[0].split('?')[0].split(':')[0]

            if cls.IP_REGEX.match(cleaned):
                return cleaned, "IPv4"
            elif cls.DOM_REGEX.match(cleaned) and '.' in cleaned:
                return cleaned, "FQDN"
            else:
                logger.warn(f"Input string failed scope structural validations: '{raw_input}'")
                return None, "INVALID"
        except Exception as e:
            logger.critical(f"Unhandled sanitization system fault occurred: {str(e)}")
            return None, "ERROR"
