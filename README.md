# Password Strength Analyzer

A comprehensive Python tool for analyzing password strength in security automation workflows. This tool provides detailed analysis of passwords based on multiple criteria including length, character variety, complexity, patterns, and entropy.

## Features

### 🔍 **Comprehensive Analysis**
- **Length Analysis**: Evaluates password length with appropriate scoring
- **Character Variety**: Checks for lowercase, uppercase, digits, and special characters
- **Complexity Analysis**: Detects common passwords, patterns, and weak substitutions
- **Pattern Detection**: Identifies sequential characters, repeated patterns, and keyboard layouts
- **Entropy Calculation**: Measures password randomness and unpredictability

### 🛡️ **Security Features**
- Common password detection
- Leet speak substitution detection
- Date and phone number pattern recognition
- Keyboard pattern identification
- Sequential character detection

### 🚀 **Automation Ready**
- Command-line interface for scripting
- JSON output format for integration
- Batch processing capabilities
- Programmatic API for custom workflows

### 🔧 **Additional Tools**
- Strong password generation
- Configurable strength thresholds
- Detailed feedback and recommendations
- Comprehensive test suite

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Optional Dependencies
For enhanced functionality, you can install additional packages:
```bash
pip install cryptography zxcvbn-python
```

## Usage

### Command Line Interface

#### Analyze a Single Password
```bash
python cli.py -p "mypassword123"
```

#### Analyze Multiple Passwords
```bash
python cli.py -p "password1" "password2" "password3"
```

#### Analyze Passwords from File
```bash
python cli.py -f passwords.txt
```

#### Generate a Strong Password
```bash
python cli.py -g -l 20
```

#### JSON Output Format
```bash
python cli.py -p "testpass" --format json
```

### Interactive Mode
```bash
python password_analyzer.py
```

### Programmatic Usage

```python
from password_analyzer import PasswordStrengthAnalyzer

# Create analyzer instance
analyzer = PasswordStrengthAnalyzer()

# Analyze a password
analysis = analyzer.analyze_password("MySecureP@ssw0rd!")

# Access results
print(f"Score: {analysis.score}/100")
print(f"Strength: {analysis.strength_level.value}")
print(f"Feedback: {analysis.feedback}")

# Generate a strong password
strong_password = analyzer.generate_strong_password(length=16)
```

## Output Examples

### Text Output
```
Password: ********
Score: 75/100
Strength: Strong
Entropy: 85.23

Feedback:
  • Good password length
  • Excellent character variety
  • Good entropy

Details:
  Length: 16 characters
  Character sets:
    - Lowercase: 8
    - Uppercase: 4
    - Digits: 2
    - Special: 2
```

### JSON Output
```json
{
  "password": "********",
  "score": 75,
  "strength_level": "Strong",
  "entropy": 85.23,
  "feedback": [
    "Good password length",
    "Excellent character variety",
    "Good entropy"
  ],
  "details": {
    "length": 16,
    "character_variety": {
      "lowercase": 8,
      "uppercase": 4,
      "digits": 2,
      "special": 2
    },
    "pattern_analysis": {
      "sequential_chars": false,
      "sequential_numbers": false,
      "repeated_chars": false,
      "keyboard_patterns": false,
      "common_password": false
    }
  }
}
```

## Strength Levels

| Level | Score Range | Description |
|-------|-------------|-------------|
| Very Weak | < 0 | Extremely weak passwords |
| Weak | 0-19 | Weak passwords with major issues |
| Medium | 20-39 | Passable but could be improved |
| Strong | 40-59 | Good security level |
| Very Strong | 60+ | Excellent security level |

## Scoring System

The analyzer uses a comprehensive scoring system:

- **Length Score** (0-30 points): Based on password length
- **Character Variety Score** (0-25 points): Mix of character types
- **Complexity Score** (-50 to 0 points): Penalties for weak patterns
- **Pattern Score** (-25 to 0 points): Penalties for predictable patterns
- **Entropy Score** (-20 to 20 points): Based on randomness

## Security Considerations

### What the Analyzer Checks

✅ **Length Requirements**
- Minimum 8 characters recommended
- Longer passwords get higher scores

✅ **Character Variety**
- Lowercase letters (a-z)
- Uppercase letters (A-Z)
- Digits (0-9)
- Special characters (!@#$%^&*)

✅ **Common Weaknesses**
- Common passwords (password, 123456, etc.)
- Sequential characters (abc, 123)
- Repeated characters (aaa, 111)
- Keyboard patterns (qwerty, asdfgh)
- Leet speak substitutions (p455w0rd)

✅ **Pattern Detection**
- Date patterns (2023, 1990)
- Phone number patterns
- Common substitutions

## Testing

Run the test suite to ensure everything works correctly:

```bash
# Run all tests
pytest test_password_analyzer.py -v

# Run with coverage
pytest test_password_analyzer.py --cov=password_analyzer --cov-report=html
```

## API Reference

### PasswordStrengthAnalyzer

#### Methods

- `analyze_password(password: str) -> PasswordAnalysis`
  - Analyzes a password and returns detailed results

- `generate_strong_password(length: int = 16, include_special: bool = True) -> str`
  - Generates a cryptographically secure password

#### Properties

- `common_passwords`: Set of known weak passwords
- `patterns`: Dictionary of regex patterns for detection

### PasswordAnalysis

#### Attributes

- `password`: The analyzed password
- `score`: Numerical score (0-100)
- `strength_level`: Enum value (VERY_WEAK, WEAK, MEDIUM, STRONG, VERY_STRONG)
- `feedback`: List of improvement suggestions
- `details`: Dictionary with detailed analysis information

## Integration Examples

### CI/CD Pipeline Integration
```python
# In your CI/CD script
analyzer = PasswordStrengthAnalyzer()
analysis = analyzer.analyze_password(user_password)

if analysis.strength_level in [StrengthLevel.VERY_WEAK, StrengthLevel.WEAK]:
    print("Password strength check failed!")
    exit(1)
```

### Web Application Integration
```python
# In your web app
def validate_password(password):
    analyzer = PasswordStrengthAnalyzer()
    analysis = analyzer.analyze_password(password)
    
    return {
        'is_valid': analysis.strength_level in [StrengthLevel.STRONG, StrengthLevel.VERY_STRONG],
        'score': analysis.score,
        'feedback': analysis.feedback
    }
```

### Batch Processing
```python
# Process multiple passwords
with open('passwords.txt', 'r') as f:
    passwords = [line.strip() for line in f]

analyzer = PasswordStrengthAnalyzer()
results = []

for password in passwords:
    analysis = analyzer.analyze_password(password)
    results.append({
        'password': password,
        'score': analysis.score,
        'strength': analysis.strength_level.value
    })
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Notice

This tool is designed for educational and security assessment purposes. Always follow your organization's security policies and guidelines when implementing password requirements.

## Support

For issues, questions, or contributions, please open an issue on the project repository. 