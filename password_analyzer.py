#!/usr/bin/env python3
"""
Password Strength Analyzer
A comprehensive tool for evaluating password strength in security automation.
"""

import re
import string
import hashlib
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum


class StrengthLevel(Enum):
    """Password strength levels."""
    VERY_WEAK = "Very Weak"
    WEAK = "Weak"
    MEDIUM = "Medium"
    STRONG = "Strong"
    VERY_STRONG = "Very Strong"


@dataclass
class PasswordAnalysis:
    """Results of password analysis."""
    password: str
    score: int
    strength_level: StrengthLevel
    feedback: List[str]
    details: Dict[str, any]


class PasswordStrengthAnalyzer:
    """Comprehensive password strength analyzer."""
    
    def __init__(self):
        # Common weak passwords and patterns
        self.common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'football', 'superman', 'trustno1'
        }
        
        # Common patterns to check
        self.patterns = {
            'sequential_chars': r'(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
            'sequential_numbers': r'(?:123|234|345|456|567|678|789|012)',
            'repeated_chars': r'(.)\1{2,}',
            'keyboard_patterns': r'(?:qwerty|asdfgh|zxcvbn|qazwsx|edcrfv|tgbyhn)'
        }
        
        # Character sets
        self.lowercase = set(string.ascii_lowercase)
        self.uppercase = set(string.ascii_uppercase)
        self.digits = set(string.digits)
        self.special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?')
    
    def analyze_password(self, password: str) -> PasswordAnalysis:
        """Analyze password strength and return detailed results."""
        if not password:
            return PasswordAnalysis(
                password="",
                score=0,
                strength_level=StrengthLevel.VERY_WEAK,
                feedback=["Password cannot be empty"],
                details={}
            )
        
        # Initialize analysis
        score = 0
        feedback = []
        details = {}
        
        # Length analysis
        length_score, length_feedback = self._analyze_length(password)
        score += length_score
        feedback.extend(length_feedback)
        details['length'] = len(password)
        details['length_score'] = length_score
        
        # Character variety analysis
        char_score, char_feedback = self._analyze_character_variety(password)
        score += char_score
        feedback.extend(char_feedback)
        details['character_variety'] = self._get_character_sets(password)
        details['char_score'] = char_score
        
        # Complexity analysis
        complexity_score, complexity_feedback = self._analyze_complexity(password)
        score += complexity_score
        feedback.extend(complexity_feedback)
        details['complexity_score'] = complexity_score
        
        # Pattern analysis
        pattern_score, pattern_feedback = self._analyze_patterns(password)
        score += pattern_score
        feedback.extend(pattern_feedback)
        details['pattern_analysis'] = self._check_patterns(password)
        details['pattern_score'] = pattern_score
        
        # Entropy analysis
        entropy_score, entropy_feedback = self._analyze_entropy(password)
        score += entropy_score
        feedback.extend(entropy_feedback)
        details['entropy'] = self._calculate_entropy(password)
        details['entropy_score'] = entropy_score
        
        # Determine strength level
        strength_level = self._determine_strength_level(score)
        
        return PasswordAnalysis(
            password=password,
            score=score,
            strength_level=strength_level,
            feedback=feedback,
            details=details
        )
    
    def _analyze_length(self, password: str) -> Tuple[int, List[str]]:
        """Analyze password length."""
        length = len(password)
        score = 0
        feedback = []
        
        if length < 8:
            score -= 20
            feedback.append("Password is too short (minimum 8 characters recommended)")
        elif length < 12:
            score += 10
            feedback.append("Password length is acceptable")
        elif length < 16:
            score += 20
            feedback.append("Good password length")
        else:
            score += 30
            feedback.append("Excellent password length")
        
        return score, feedback
    
    def _analyze_character_variety(self, password: str) -> Tuple[int, List[str]]:
        """Analyze character variety in password."""
        score = 0
        feedback = []
        
        has_lowercase = any(c in self.lowercase for c in password)
        has_uppercase = any(c in self.uppercase for c in password)
        has_digits = any(c in self.digits for c in password)
        has_special = any(c in self.special_chars for c in password)
        
        if has_lowercase:
            score += 5
        else:
            feedback.append("Add lowercase letters")
        
        if has_uppercase:
            score += 5
        else:
            feedback.append("Add uppercase letters")
        
        if has_digits:
            score += 5
        else:
            feedback.append("Add numbers")
        
        if has_special:
            score += 10
        else:
            feedback.append("Add special characters")
        
        # Bonus for having all character types
        if all([has_lowercase, has_uppercase, has_digits, has_special]):
            score += 10
            feedback.append("Excellent character variety")
        
        return score, feedback
    
    def _analyze_complexity(self, password: str) -> Tuple[int, List[str]]:
        """Analyze password complexity."""
        score = 0
        feedback = []
        
        # Check for common passwords
        if password.lower() in self.common_passwords:
            score -= 50
            feedback.append("Password is a common weak password")
        
        # Check for repeated characters
        if re.search(r'(.)\1{3,}', password):
            score -= 15
            feedback.append("Avoid repeated characters")
        
        # Check for sequential characters
        if re.search(self.patterns['sequential_chars'], password.lower()):
            score -= 20
            feedback.append("Avoid sequential letters")
        
        if re.search(self.patterns['sequential_numbers'], password):
            score -= 20
            feedback.append("Avoid sequential numbers")
        
        # Check for keyboard patterns
        if re.search(self.patterns['keyboard_patterns'], password.lower()):
            score -= 25
            feedback.append("Avoid keyboard patterns")
        
        return score, feedback
    
    def _analyze_patterns(self, password: str) -> Tuple[int, List[str]]:
        """Analyze password patterns."""
        score = 0
        feedback = []
        
        # Check for date patterns (YYYY, YYYYMM, YYYYMMDD)
        if re.search(r'\d{4}', password):
            score -= 10
            feedback.append("Avoid date patterns")
        
        # Check for phone number patterns
        if re.search(r'\d{3}[-.]?\d{3}[-.]?\d{4}', password):
            score -= 15
            feedback.append("Avoid phone number patterns")
        
        # Check for common substitutions (1337 speak)
        leet_speak = password.lower()
        leet_speak = leet_speak.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's').replace('7', 't')
        if leet_speak in self.common_passwords:
            score -= 20
            feedback.append("Avoid common leet speak substitutions")
        
        return score, feedback
    
    def _analyze_entropy(self, password: str) -> Tuple[int, List[str]]:
        """Analyze password entropy."""
        score = 0
        feedback = []
        
        entropy = self._calculate_entropy(password)
        
        if entropy < 30:
            score -= 20
            feedback.append("Very low entropy - password is too predictable")
        elif entropy < 50:
            score -= 10
            feedback.append("Low entropy - consider more randomness")
        elif entropy < 70:
            score += 10
            feedback.append("Good entropy")
        else:
            score += 20
            feedback.append("Excellent entropy")
        
        return score, feedback
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy."""
        char_sets = self._get_character_sets(password)
        charset_size = sum(char_sets.values())
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * (charset_size ** 0.5)
        return entropy
    
    def _get_character_sets(self, password: str) -> Dict[str, int]:
        """Get character set information."""
        sets = {
            'lowercase': len(set(password) & self.lowercase),
            'uppercase': len(set(password) & self.uppercase),
            'digits': len(set(password) & self.digits),
            'special': len(set(password) & self.special_chars)
        }
        return sets
    
    def _check_patterns(self, password: str) -> Dict[str, bool]:
        """Check for various patterns in password."""
        return {
            'sequential_chars': bool(re.search(self.patterns['sequential_chars'], password.lower())),
            'sequential_numbers': bool(re.search(self.patterns['sequential_numbers'], password)),
            'repeated_chars': bool(re.search(self.patterns['repeated_chars'], password)),
            'keyboard_patterns': bool(re.search(self.patterns['keyboard_patterns'], password.lower())),
            'common_password': password.lower() in self.common_passwords
        }
    
    def _determine_strength_level(self, score: int) -> StrengthLevel:
        """Determine strength level based on score."""
        if score < 0:
            return StrengthLevel.VERY_WEAK
        elif score < 20:
            return StrengthLevel.WEAK
        elif score < 40:
            return StrengthLevel.MEDIUM
        elif score < 60:
            return StrengthLevel.STRONG
        else:
            return StrengthLevel.VERY_STRONG
    
    def generate_strong_password(self, length: int = 16, include_special: bool = True) -> str:
        """Generate a strong password."""
        import secrets
        
        charset = string.ascii_letters + string.digits
        if include_special:
            charset += string.punctuation
        
        # Ensure at least one character from each set
        password = []
        password.append(secrets.choice(string.ascii_lowercase))
        password.append(secrets.choice(string.ascii_uppercase))
        password.append(secrets.choice(string.digits))
        if include_special:
            password.append(secrets.choice(string.punctuation))
        
        # Fill the rest randomly
        remaining_length = length - len(password)
        password.extend(secrets.choice(charset) for _ in range(remaining_length))
        
        # Shuffle the password
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        
        return ''.join(password_list)


def main():
    """Main function for command-line usage."""
    analyzer = PasswordStrengthAnalyzer()
    
    print("Password Strength Analyzer")
    print("=" * 50)
    
    while True:
        password = input("\nEnter password to analyze (or 'quit' to exit): ").strip()
        
        if password.lower() in ['quit', 'exit', 'q']:
            break
        
        if not password:
            print("Please enter a password.")
            continue
        
        # Analyze password
        analysis = analyzer.analyze_password(password)
        
        # Display results
        print(f"\nPassword: {'*' * len(password)}")
        print(f"Score: {analysis.score}/100")
        print(f"Strength: {analysis.strength_level.value}")
        print(f"Entropy: {analysis.details.get('entropy', 0):.2f}")
        
        print("\nFeedback:")
        for feedback in analysis.feedback:
            print(f"  • {feedback}")
        
        print("\nDetails:")
        print(f"  Length: {analysis.details.get('length', 0)} characters")
        char_sets = analysis.details.get('character_variety', {})
        print(f"  Character sets: {char_sets}")
        
        # Offer to generate a strong password
        if analysis.strength_level in [StrengthLevel.VERY_WEAK, StrengthLevel.WEAK]:
            generate = input("\nWould you like a strong password suggestion? (y/n): ").strip().lower()
            if generate == 'y':
                strong_password = analyzer.generate_strong_password()
                print(f"Suggested strong password: {strong_password}")


if __name__ == "__main__":
    main() 