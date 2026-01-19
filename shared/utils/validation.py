"""
Validation utilities for lead data
"""
import re
from typing import Optional, Dict, Any, Tuple
from email_validator import validate_email, EmailNotValidError


def validate_email_format(email: str) -> bool:
    """Validate email format"""
    if not email:
        return False
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False


def validate_phone_format(phone: str) -> bool:
    """Validate phone number format (basic validation)"""
    if not phone:
        return False
    # Remove common separators
    cleaned = re.sub(r'[\s\-\(\)\+]', '', phone)
    # Check if it's digits and reasonable length (7-15 digits)
    return cleaned.isdigit() and 7 <= len(cleaned) <= 15


def normalize_phone(phone: str) -> Optional[str]:
    """Normalize phone number"""
    if not phone:
        return None
    # Remove all non-digit characters except +
    cleaned = re.sub(r'[^\d+]', '', phone)
    # Ensure it starts with + if it has country code
    if cleaned and not cleaned.startswith('+'):
        # Assume default country code if needed (customize per client)
        cleaned = f"+{cleaned}"
    return cleaned


def is_suspicious_lead(lead_data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Check if lead data looks suspicious/spammy
    
    Returns:
        Tuple of (is_suspicious, reason)
    """
    # Check for suspicious patterns
    name = lead_data.get("name", "").strip().lower()
    email = lead_data.get("email", "").strip().lower()
    
    # Suspicious name patterns
    suspicious_names = [
        "test", "spam", "fake", "dummy", "admin", "root",
        "user", "guest", "anonymous", "n/a", "na"
    ]
    if name in suspicious_names or len(name) < 2:
        return True, "Suspicious name pattern"
    
    # Suspicious email patterns
    if email:
        suspicious_domains = [
            "test.com", "example.com", "fake.com", "spam.com",
            "mailinator.com", "10minutemail.com"
        ]
        email_domain = email.split("@")[-1] if "@" in email else ""
        if email_domain in suspicious_domains:
            return True, "Suspicious email domain"
        
        # Check for disposable email patterns
        if any(pattern in email for pattern in ["temp", "throwaway", "trash"]):
            return True, "Disposable email detected"
    
    # Check for too many special characters in name
    if name and len(re.findall(r'[^a-z\s]', name)) > len(name) * 0.3:
        return True, "Too many special characters in name"
    
    return False, None

