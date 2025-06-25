#!/usr/bin/env python3
"""
Unit tests for Password Strength Analyzer
"""

import pytest
from password_analyzer import PasswordStrengthAnalyzer, StrengthLevel, PasswordAnalysis


class TestPasswordStrengthAnalyzer:
    """Test cases for PasswordStrengthAnalyzer."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = PasswordStrengthAnalyzer()
    
    def test_empty_password(self):
        """Test analysis of empty password."""
        analysis = self.analyzer.analyze_password("")
        assert analysis.score == 0
        assert analysis.strength_level == StrengthLevel.VERY_WEAK
        assert "Password cannot be empty" in analysis.feedback
    
    def test_very_weak_password(self):
        """Test analysis of very weak password."""
        analysis = self.analyzer.analyze_password("123")
        assert analysis.score < 0
        assert analysis.strength_level == StrengthLevel.VERY_WEAK
        assert "too short" in analysis.feedback[0]
    
    def test_weak_password(self):
        """Test analysis of weak password."""
        analysis = self.analyzer.analyze_password("password")
        assert analysis.strength_level == StrengthLevel.WEAK
        assert "common weak password" in analysis.feedback
    
    def test_medium_password(self):
        """Test analysis of medium strength password."""
        analysis = self.analyzer.analyze_password("Password123")
        assert analysis.strength_level == StrengthLevel.MEDIUM
    
    def test_strong_password(self):
        """Test analysis of strong password."""
        analysis = self.analyzer.analyze_password("MySecureP@ssw0rd!")
        assert analysis.strength_level in [StrengthLevel.STRONG, StrengthLevel.VERY_STRONG]
    
    def test_very_strong_password(self):
        """Test analysis of very strong password."""
        analysis = self.analyzer.analyze_password("K9#mN2$pL8@vX5&qR7!")
        assert analysis.strength_level == StrengthLevel.VERY_STRONG
        assert analysis.score >= 60
    
    def test_length_analysis(self):
        """Test length-based scoring."""
        # Short password
        analysis = self.analyzer.analyze_password("abc")
        assert analysis.details['length_score'] < 0
        
        # Medium password
        analysis = self.analyzer.analyze_password("abcdefgh")
        assert analysis.details['length_score'] >= 0
        
        # Long password
        analysis = self.analyzer.analyze_password("abcdefghijklmnop")
        assert analysis.details['length_score'] >= 20
    
    def test_character_variety(self):
        """Test character variety analysis."""
        # Only lowercase
        analysis = self.analyzer.analyze_password("abcdefgh")
        assert "Add uppercase letters" in analysis.feedback
        assert "Add numbers" in analysis.feedback
        
        # All character types
        analysis = self.analyzer.analyze_password("Abc123!@#")
        assert "Excellent character variety" in analysis.feedback
    
    def test_common_passwords(self):
        """Test detection of common passwords."""
        analysis = self.analyzer.analyze_password("password")
        assert "common weak password" in analysis.feedback
        assert analysis.details['pattern_analysis']['common_password'] is True
    
    def test_sequential_patterns(self):
        """Test detection of sequential patterns."""
        analysis = self.analyzer.analyze_password("abc123")
        assert "sequential letters" in analysis.feedback or "sequential numbers" in analysis.feedback
    
    def test_repeated_characters(self):
        """Test detection of repeated characters."""
        analysis = self.analyzer.analyze_password("aaa123")
        assert "repeated characters" in analysis.feedback
    
    def test_keyboard_patterns(self):
        """Test detection of keyboard patterns."""
        analysis = self.analyzer.analyze_password("qwerty")
        assert "keyboard patterns" in analysis.feedback
    
    def test_entropy_calculation(self):
        """Test entropy calculation."""
        # Low entropy password
        analysis = self.analyzer.analyze_password("aaaa")
        assert analysis.details['entropy'] < 30
        
        # High entropy password
        analysis = self.analyzer.analyze_password("K9#mN2$pL8@vX5&qR7!")
        assert analysis.details['entropy'] > 50
    
    def test_generate_strong_password(self):
        """Test password generation."""
        password = self.analyzer.generate_strong_password(length=16)
        assert len(password) == 16
        
        # Analyze generated password
        analysis = self.analyzer.analyze_password(password)
        assert analysis.strength_level in [StrengthLevel.STRONG, StrengthLevel.VERY_STRONG]
        
        # Check character variety
        char_sets = analysis.details['character_variety']
        assert char_sets['lowercase'] > 0
        assert char_sets['uppercase'] > 0
        assert char_sets['digits'] > 0
    
    def test_generate_password_without_special(self):
        """Test password generation without special characters."""
        password = self.analyzer.generate_strong_password(length=12, include_special=False)
        assert len(password) == 12
        
        # Should not contain special characters
        special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?')
        assert not any(c in special_chars for c in password)
    
    def test_leet_speak_detection(self):
        """Test detection of leet speak substitutions."""
        analysis = self.analyzer.analyze_password("p455w0rd")
        # Should detect that this is a leet speak version of "password"
        assert "leet speak" in analysis.feedback
    
    def test_date_patterns(self):
        """Test detection of date patterns."""
        analysis = self.analyzer.analyze_password("password2023")
        assert "date patterns" in analysis.feedback
    
    def test_phone_patterns(self):
        """Test detection of phone number patterns."""
        analysis = self.analyzer.analyze_password("password123-456-7890")
        assert "phone number patterns" in analysis.feedback
    
    def test_character_sets_detection(self):
        """Test character set detection."""
        password = "Abc123!@#"
        char_sets = self.analyzer._get_character_sets(password)
        
        assert char_sets['lowercase'] > 0
        assert char_sets['uppercase'] > 0
        assert char_sets['digits'] > 0
        assert char_sets['special'] > 0
    
    def test_pattern_detection(self):
        """Test pattern detection methods."""
        password = "abc123aaa"
        patterns = self.analyzer._check_patterns(password)
        
        assert isinstance(patterns, dict)
        assert 'sequential_chars' in patterns
        assert 'sequential_numbers' in patterns
        assert 'repeated_chars' in patterns
        assert 'keyboard_patterns' in patterns
        assert 'common_password' in patterns


class TestStrengthLevels:
    """Test strength level determination."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = PasswordStrengthAnalyzer()
    
    def test_strength_level_ranges(self):
        """Test that strength levels are assigned correctly based on scores."""
        # Test very weak
        analysis = self.analyzer.analyze_password("123")
        assert analysis.strength_level == StrengthLevel.VERY_WEAK
        
        # Test weak
        analysis = self.analyzer.analyze_password("password")
        assert analysis.strength_level == StrengthLevel.WEAK
        
        # Test medium
        analysis = self.analyzer.analyze_password("Password123")
        assert analysis.strength_level == StrengthLevel.MEDIUM
        
        # Test strong
        analysis = self.analyzer.analyze_password("MySecureP@ssw0rd!")
        assert analysis.strength_level in [StrengthLevel.STRONG, StrengthLevel.VERY_STRONG]


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 