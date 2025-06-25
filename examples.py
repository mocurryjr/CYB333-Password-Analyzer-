#!/usr/bin/env python3
"""
Examples and usage patterns for Password Strength Analyzer
"""

from password_analyzer import PasswordStrengthAnalyzer, StrengthLevel
import json


def basic_usage_example():
    """Basic usage example."""
    print("=== Basic Usage Example ===")
    
    analyzer = PasswordStrengthAnalyzer()
    
    # Analyze a password
    password = "MySecureP@ssw0rd!"
    analysis = analyzer.analyze_password(password)
    
    print(f"Password: {password}")
    print(f"Score: {analysis.score}/100")
    print(f"Strength: {analysis.strength_level.value}")
    print(f"Feedback: {analysis.feedback}")
    print()


def batch_analysis_example():
    """Example of analyzing multiple passwords."""
    print("=== Batch Analysis Example ===")
    
    passwords = [
        "password",
        "123456",
        "MySecureP@ssw0rd!",
        "qwerty",
        "K9#mN2$pL8@vX5&qR7!"
    ]
    
    analyzer = PasswordStrengthAnalyzer()
    results = []
    
    for password in passwords:
        analysis = analyzer.analyze_password(password)
        results.append({
            'password': password,
            'score': analysis.score,
            'strength': analysis.strength_level.value,
            'feedback': analysis.feedback
        })
    
    # Print results in a table format
    print(f"{'Password':<20} {'Score':<8} {'Strength':<12}")
    print("-" * 40)
    for result in results:
        print(f"{result['password']:<20} {result['score']:<8} {result['strength']:<12}")
    print()


def password_generation_example():
    """Example of generating strong passwords."""
    print("=== Password Generation Example ===")
    
    analyzer = PasswordStrengthAnalyzer()
    
    # Generate different types of passwords
    print("Generated passwords:")
    for i in range(3):
        password = analyzer.generate_strong_password(length=16)
        analysis = analyzer.analyze_password(password)
        print(f"Password {i+1}: {password}")
        print(f"  Score: {analysis.score}/100, Strength: {analysis.strength_level.value}")
    
    # Generate password without special characters
    password_no_special = analyzer.generate_strong_password(length=12, include_special=False)
    analysis = analyzer.analyze_password(password_no_special)
    print(f"Password (no special): {password_no_special}")
    print(f"  Score: {analysis.score}/100, Strength: {analysis.strength_level.value}")
    print()


def detailed_analysis_example():
    """Example showing detailed analysis information."""
    print("=== Detailed Analysis Example ===")
    
    analyzer = PasswordStrengthAnalyzer()
    password = "MySecureP@ssw0rd2023!"
    analysis = analyzer.analyze_password(password)
    
    print(f"Password: {password}")
    print(f"Overall Score: {analysis.score}/100")
    print(f"Strength Level: {analysis.strength_level.value}")
    print(f"Entropy: {analysis.details.get('entropy', 0):.2f}")
    
    print("\nDetailed Scoring:")
    print(f"  Length Score: {analysis.details.get('length_score', 0)}")
    print(f"  Character Variety Score: {analysis.details.get('char_score', 0)}")
    print(f"  Complexity Score: {analysis.details.get('complexity_score', 0)}")
    print(f"  Pattern Score: {analysis.details.get('pattern_score', 0)}")
    print(f"  Entropy Score: {analysis.details.get('entropy_score', 0)}")
    
    print("\nCharacter Sets:")
    char_sets = analysis.details.get('character_variety', {})
    for char_type, count in char_sets.items():
        print(f"  {char_type.title()}: {count}")
    
    print("\nPattern Analysis:")
    patterns = analysis.details.get('pattern_analysis', {})
    for pattern, detected in patterns.items():
        status = "✓ Detected" if detected else "✗ Not detected"
        print(f"  {pattern.replace('_', ' ').title()}: {status}")
    
    print("\nFeedback:")
    for feedback in analysis.feedback:
        print(f"  • {feedback}")
    print()


def security_automation_example():
    """Example of using the analyzer in security automation."""
    print("=== Security Automation Example ===")
    
    analyzer = PasswordStrengthAnalyzer()
    
    # Simulate password validation in a web application
    def validate_password_for_registration(password):
        """Validate password during user registration."""
        analysis = analyzer.analyze_password(password)
        
        # Define security requirements
        min_score = 40  # Minimum score required
        min_strength = StrengthLevel.STRONG
        
        is_valid = (analysis.score >= min_score and 
                   analysis.strength_level in [StrengthLevel.STRONG, StrengthLevel.VERY_STRONG])
        
        return {
            'is_valid': is_valid,
            'score': analysis.score,
            'strength_level': analysis.strength_level.value,
            'feedback': analysis.feedback,
            'meets_requirements': is_valid
        }
    
    # Test different passwords
    test_passwords = [
        "weak",
        "password123",
        "MySecureP@ssw0rd!",
        "K9#mN2$pL8@vX5&qR7!"
    ]
    
    print("Password Validation Results:")
    print(f"{'Password':<20} {'Valid':<8} {'Score':<8} {'Meets Req':<12}")
    print("-" * 50)
    
    for password in test_passwords:
        result = validate_password_for_registration(password)
        print(f"{password:<20} {str(result['is_valid']):<8} {result['score']:<8} {str(result['meets_requirements']):<12}")
    print()


def json_output_example():
    """Example of JSON output for API integration."""
    print("=== JSON Output Example ===")
    
    analyzer = PasswordStrengthAnalyzer()
    password = "MySecureP@ssw0rd!"
    analysis = analyzer.analyze_password(password)
    
    # Convert to JSON-serializable format
    result = {
        "password": "*" * len(analysis.password),
        "score": analysis.score,
        "strength_level": analysis.strength_level.value,
        "entropy": round(analysis.details.get('entropy', 0), 2),
        "feedback": analysis.feedback,
        "details": {
            "length": analysis.details.get('length', 0),
            "character_variety": analysis.details.get('character_variety', {}),
            "pattern_analysis": analysis.details.get('pattern_analysis', {}),
            "scoring_breakdown": {
                "length_score": analysis.details.get('length_score', 0),
                "char_score": analysis.details.get('char_score', 0),
                "complexity_score": analysis.details.get('complexity_score', 0),
                "pattern_score": analysis.details.get('pattern_score', 0),
                "entropy_score": analysis.details.get('entropy_score', 0)
            }
        }
    }
    
    print("JSON Output:")
    print(json.dumps(result, indent=2))
    print()


def ci_cd_integration_example():
    """Example of CI/CD pipeline integration."""
    print("=== CI/CD Integration Example ===")
    
    analyzer = PasswordStrengthAnalyzer()
    
    # Simulate checking passwords in a CI/CD pipeline
    def check_password_strength_in_pipeline(passwords):
        """Check password strength in CI/CD pipeline."""
        failed_passwords = []
        
        for password in passwords:
            analysis = analyzer.analyze_password(password)
            
            # Fail if password is weak
            if analysis.strength_level in [StrengthLevel.VERY_WEAK, StrengthLevel.WEAK]:
                failed_passwords.append({
                    'password': password,
                    'score': analysis.score,
                    'strength': analysis.strength_level.value,
                    'feedback': analysis.feedback
                })
        
        return failed_passwords
    
    # Test passwords
    test_passwords = [
        "weak123",
        "password",
        "MySecureP@ssw0rd!",
        "123456"
    ]
    
    failed = check_password_strength_in_pipeline(test_passwords)
    
    if failed:
        print("❌ Password strength check failed!")
        print("Weak passwords found:")
        for pwd in failed:
            print(f"  - {pwd['password']} (Score: {pwd['score']}, Strength: {pwd['strength']})")
        print("Pipeline should fail here.")
    else:
        print("✅ All passwords meet strength requirements.")
    print()


def custom_threshold_example():
    """Example of using custom thresholds."""
    print("=== Custom Thresholds Example ===")
    
    analyzer = PasswordStrengthAnalyzer()
    
    # Define custom security requirements
    custom_requirements = {
        'min_length': 12,
        'min_score': 60,
        'require_special_chars': True,
        'require_mixed_case': True,
        'require_numbers': True
    }
    
    def validate_with_custom_requirements(password):
        """Validate password with custom requirements."""
        analysis = analyzer.analyze_password(password)
        
        # Check custom requirements
        char_sets = analysis.details.get('character_variety', {})
        
        requirements_met = {
            'length': analysis.details.get('length', 0) >= custom_requirements['min_length'],
            'score': analysis.score >= custom_requirements['min_score'],
            'special_chars': char_sets.get('special', 0) > 0 if custom_requirements['require_special_chars'] else True,
            'mixed_case': (char_sets.get('lowercase', 0) > 0 and char_sets.get('uppercase', 0) > 0) if custom_requirements['require_mixed_case'] else True,
            'numbers': char_sets.get('digits', 0) > 0 if custom_requirements['require_numbers'] else True
        }
        
        all_met = all(requirements_met.values())
        
        return {
            'is_valid': all_met,
            'requirements_met': requirements_met,
            'analysis': analysis
        }
    
    # Test passwords
    test_passwords = [
        "short",
        "MySecureP@ssw0rd!",
        "nouppercase123!",
        "K9#mN2$pL8@vX5&qR7!"
    ]
    
    print("Custom Requirements Validation:")
    for password in test_passwords:
        result = validate_with_custom_requirements(password)
        print(f"\nPassword: {password}")
        print(f"Valid: {result['is_valid']}")
        print("Requirements:")
        for req, met in result['requirements_met'].items():
            status = "✅" if met else "❌"
            print(f"  {status} {req.replace('_', ' ').title()}")
    print()


def main():
    """Run all examples."""
    print("Password Strength Analyzer - Examples")
    print("=" * 50)
    
    basic_usage_example()
    batch_analysis_example()
    password_generation_example()
    detailed_analysis_example()
    security_automation_example()
    json_output_example()
    ci_cd_integration_example()
    custom_threshold_example()
    
    print("All examples completed!")


if __name__ == "__main__":
    main() 