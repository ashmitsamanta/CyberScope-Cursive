"""
password_strength.py

Scores a password on a 0-10 point scale (grades A+ to F), evaluating length
(weighted heavily), character variety, predictability (repeated/sequential runs),
and rejects known-common passwords outright.
"""

from string import punctuation


COMMON_PASSWORDS = {
    "password", "password1", "password1234", "123456", "12345678",
    "qwerty", "qwerty123", "letmein", "admin", "welcome",
    "iloveyou", "monkey", "dragon", "111111", "abc123",
    "passw0rd", "password1!", "p@ssword", "p@ssw0rd",
}


def check_password_strength(password: str) -> tuple:
    """
    Analyse a password and return (score, max_score, grade, rating, reasons).

    * score     – integer 0..max_score (0-10 scale)
    * max_score – integer (10)
    * grade     – string ("A+", "A", "B+", "B", "C", "D", "F")
    * rating    – string ("STRONG", "MEDIUM", "TOO WEAK")
    * reasons   – list of human-readable improvement tips
    """
    reasons: list[str] = []
    score = 0
    max_score = 10

    if not password:
        return 0, max_score, "F", "TOO WEAK", ["Password cannot be empty."]

    # Known-common password -> instant fail (0/10)
    if password.lower() in COMMON_PASSWORDS:
        reasons.append(
            "This password appears on common compromised lists. Choose something unpredictable."
        )
        return 0, max_score, "F", "TOO WEAK", reasons

    # 1. Length scoring (up to 4 points out of 10)
    length = len(password)
    if length >= 16:
        score += 4
    elif length >= 12:
        score += 3
    elif length >= 8:
        score += 2
    else:
        reasons.append(
            "Password is too short. Aim for 12+ characters — length beats complexity."
        )

    # 2. Character set variety scoring (4 points out of 10)
    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(char in punctuation for char in password)

    if has_digit:
        score += 1
    else:
        reasons.append("Add at least one digit (0-9).")

    if has_upper:
        score += 1
    else:
        reasons.append("Add at least one uppercase letter (A-Z).")

    if has_lower:
        score += 1
    else:
        reasons.append("Add at least one lowercase letter (a-z).")

    if has_special:
        score += 1
    else:
        reasons.append("Add at least one special character (!@#$%^&*).")

    # 3. Variety & Length Bonuses (up to 2 points out of 10)
    char_types_count = sum([has_digit, has_upper, has_lower, has_special])
    if char_types_count == 4:
        score += 1

    if length >= 14 and char_types_count >= 3:
        score += 1

    # 4. Pattern / Predictability Deductions
    if _has_repeated_or_sequential_run(password):
        reasons.append(
            "Avoid repeated or sequential characters (e.g. 'aaa', '123', 'abc')."
        )
        score = max(0, score - 1)

    score = min(max_score, max(0, score))
    grade = get_password_grade(score, max_score)
    rating = rate_strength(score, max_score)

    return score, max_score, grade, rating, reasons


def _has_repeated_or_sequential_run(password: str, run_length: int = 3) -> bool:
    """Detect runs like 'aaa', '111', or ascending sequences like 'abc', '123'."""
    for i in range(len(password) - run_length + 1):
        window = password[i : i + run_length]
        # All identical characters
        if len(set(window)) == 1:
            return True
        # Ascending consecutive code-points
        codes = [ord(c) for c in window]
        if all(codes[j] + 1 == codes[j + 1] for j in range(len(codes) - 1)):
            return True
    return False


def get_password_grade(score: int, max_score: int = 10) -> str:
    """Convert 0-10 numeric score to a Letter Grade."""
    normalized = (score / max_score) * 10
    if normalized >= 9.5:
        return "A+"
    elif normalized >= 8.5:
        return "A"
    elif normalized >= 7.5:
        return "B+"
    elif normalized >= 6.5:
        return "B"
    elif normalized >= 5.0:
        return "C"
    elif normalized >= 3.0:
        return "D"
    else:
        return "F"


def rate_strength(score: int, max_score: int = 10) -> str:
    """Convert numeric score to human-readable rating (STRONG, MEDIUM, TOO WEAK)."""
    ratio = score / max_score
    if ratio >= 0.7:
        return "STRONG"
    elif ratio >= 0.4:
        return "MEDIUM"
    else:
        return "TOO WEAK"

