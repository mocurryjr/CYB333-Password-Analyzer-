#!/usr/bin/env python3
"""
Command Line Interface for Password Strength Analyzer
"""

import argparse
import json
import sys
from typing import List
from password_analyzer import PasswordStrengthAnalyzer, StrengthLevel


class PasswordAnalyzerCLI:
    """Command-line interface for password strength analysis."""
    
    def __init__(self):
        self.analyzer = PasswordStrengthAnalyzer()
    
    def analyze_single_password(self, password: str, output_format: str = "text") -> None:
        """Analyze a single password and display results."""
        analysis = self.analyzer.analyze_password(password)
        
        if output_format == "json":
            self._output_json(analysis)
        else:
            self._output_text(analysis)
    
    def analyze_file(self, filepath: str, output_format: str = "text") -> None:
        """Analyze passwords from a file (one per line)."""
        try:
            with open(filepath, 'r') as file:
                passwords = [line.strip() for line in file if line.strip()]
            
            if output_format == "json":
                results = []
                for password in passwords:
                    analysis = self.analyzer.analyze_password(password)
                    results.append(self._analysis_to_dict(analysis))
                print(json.dumps(results, indent=2))
            else:
                for i, password in enumerate(passwords, 1):
                    print(f"\n--- Password {i} ---")
                    analysis = self.analyzer.analyze_password(password)
                    self._output_text(analysis, show_password=False)
                    
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
    
    def generate_password(self, length: int = 16, include_special: bool = True) -> None:
        """Generate a strong password."""
        password = self.analyzer.generate_strong_password(length, include_special)
        print(f"Generated password: {password}")
        
        # Analyze the generated password
        analysis = self.analyzer.analyze_password(password)
        print(f"Strength: {analysis.strength_level.value}")
        print(f"Score: {analysis.score}/100")
    
    def batch_analysis(self, passwords: List[str], output_format: str = "text") -> None:
        """Analyze multiple passwords."""
        if output_format == "json":
            results = []
            for password in passwords:
                analysis = self.analyzer.analyze_password(password)
                results.append(self._analysis_to_dict(analysis))
            print(json.dumps(results, indent=2))
        else:
            for i, password in enumerate(passwords, 1):
                print(f"\n--- Password {i} ---")
                analysis = self.analyzer.analyze_password(password)
                self._output_text(analysis, show_password=False)
    
    def _output_text(self, analysis, show_password: bool = True) -> None:
        """Output analysis results in text format."""
        if show_password:
            print(f"Password: {'*' * len(analysis.password)}")
        
        print(f"Score: {analysis.score}/100")
        print(f"Strength: {analysis.strength_level.value}")
        print(f"Entropy: {analysis.details.get('entropy', 0):.2f}")
        
        print("\nFeedback:")
        for feedback in analysis.feedback:
            print(f"  • {feedback}")
        
        print("\nDetails:")
        print(f"  Length: {analysis.details.get('length', 0)} characters")
        
        char_sets = analysis.details.get('character_variety', {})
        print(f"  Character sets:")
        print(f"    - Lowercase: {char_sets.get('lowercase', 0)}")
        print(f"    - Uppercase: {char_sets.get('uppercase', 0)}")
        print(f"    - Digits: {char_sets.get('digits', 0)}")
        print(f"    - Special: {char_sets.get('special', 0)}")
        
        patterns = analysis.details.get('pattern_analysis', {})
        if any(patterns.values()):
            print(f"  Patterns detected:")
            for pattern, detected in patterns.items():
                if detected:
                    print(f"    - {pattern.replace('_', ' ').title()}")
    
    def _output_json(self, analysis) -> None:
        """Output analysis results in JSON format."""
        result = self._analysis_to_dict(analysis)
        print(json.dumps(result, indent=2))
    
    def _analysis_to_dict(self, analysis) -> dict:
        """Convert analysis to dictionary for JSON output."""
        return {
            "password": "*" * len(analysis.password),
            "score": analysis.score,
            "strength_level": analysis.strength_level.value,
            "entropy": round(analysis.details.get('entropy', 0), 2),
            "feedback": analysis.feedback,
            "details": {
                "length": analysis.details.get('length', 0),
                "character_variety": analysis.details.get('character_variety', {}),
                "pattern_analysis": analysis.details.get('pattern_analysis', {}),
                "length_score": analysis.details.get('length_score', 0),
                "char_score": analysis.details.get('char_score', 0),
                "complexity_score": analysis.details.get('complexity_score', 0),
                "pattern_score": analysis.details.get('pattern_score', 0),
                "entropy_score": analysis.details.get('entropy_score', 0)
            }
        }


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description="Password Strength Analyzer - A comprehensive tool for evaluating password strength",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -p "mypassword123"
  %(prog)s -f passwords.txt
  %(prog)s -g -l 20
  %(prog)s -p "password1" "password2" "password3"
  %(prog)s -p "testpass" --format json
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '-p', '--password',
        nargs='+',
        help='Password(s) to analyze'
    )
    input_group.add_argument(
        '-f', '--file',
        help='File containing passwords (one per line)'
    )
    input_group.add_argument(
        '-g', '--generate',
        action='store_true',
        help='Generate a strong password'
    )
    
    # Output options
    parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    
    # Generation options
    parser.add_argument(
        '-l', '--length',
        type=int,
        default=16,
        help='Length of generated password (default: 16)'
    )
    parser.add_argument(
        '--no-special',
        action='store_true',
        help='Exclude special characters from generated password'
    )
    
    # Additional options
    parser.add_argument(
        '--version',
        action='version',
        version='Password Strength Analyzer 1.0.0'
    )
    
    args = parser.parse_args()
    
    cli = PasswordAnalyzerCLI()
    
    try:
        if args.generate:
            cli.generate_password(args.length, not args.no_special)
        elif args.file:
            cli.analyze_file(args.file, args.format)
        elif args.password:
            if len(args.password) == 1:
                cli.analyze_single_password(args.password[0], args.format)
            else:
                cli.batch_analysis(args.password, args.format)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 