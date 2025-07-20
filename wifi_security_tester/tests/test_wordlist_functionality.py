#!/usr/bin/env python3
"""
Test script for wordlist management functionality
"""

import sys
import os
import tempfile
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent / "wifi_security_tester"
sys.path.insert(0, str(project_root))

from components.wordlist_manager import WordlistManager

def test_wordlist_functionality():
    """Test core wordlist management functionality"""
    print("Testing wordlist management functionality...")
    
    try:
        wordlist_manager = WordlistManager()
        
        # Test 1: Create built-in wordlist
        print("\n1. Testing built-in wordlist creation...")
        passwords = wordlist_manager.generate_builtin_wordlist('common')
        assert len(passwords) > 0, "Should generate common passwords"
        print(f"✓ Generated {len(passwords)} common passwords")
        
        # Test 2: Create custom wordlist
        print("\n2. Testing custom wordlist creation...")
        test_passwords = ['password123', 'test1234', 'wifi2024', 'admin123']
        success, result = wordlist_manager.create_custom_wordlist(
            'test_custom', test_passwords, 'Test custom wordlist'
        )
        assert success, f"Should create custom wordlist: {result}"
        print(f"✓ Created custom wordlist: {result}")
        
        # Test 3: Get available wordlists
        print("\n3. Testing wordlist listing...")
        wordlists = wordlist_manager.get_available_wordlists()
        assert len(wordlists) > 0, "Should have available wordlists"
        
        builtin_count = sum(1 for w in wordlists.values() if w.get('type') == 'builtin')
        custom_count = sum(1 for w in wordlists.values() if w.get('type') == 'custom')
        print(f"✓ Found {builtin_count} built-in and {custom_count} custom wordlists")
        
        # Test 4: Create temporary wordlist file for import test
        print("\n4. Testing wordlist import...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
            temp_passwords = ['import1', 'import2', 'import3', 'validpassword123']
            for pwd in temp_passwords:
                temp_file.write(f"{pwd}\n")
            temp_file_path = temp_file.name
        
        try:
            success, message, count = wordlist_manager.import_wordlist(temp_file_path, validate=True)
            assert success, f"Should import wordlist: {message}"
            assert count > 0, "Should import some passwords"
            print(f"✓ Imported {count} passwords from file")
        finally:
            os.unlink(temp_file_path)
        
        # Test 5: Combine wordlists
        print("\n5. Testing wordlist combination...")
        success, result = wordlist_manager.create_combined_wordlist(
            'test_combined', ['builtin_common', 'test_custom'], remove_duplicates=True
        )
        assert success, f"Should combine wordlists: {result}"
        print(f"✓ Combined wordlists: {result}")
        
        # Test 6: Analyze wordlist
        print("\n6. Testing wordlist analysis...")
        # Find a custom wordlist to analyze
        custom_wordlists = {k: v for k, v in wordlists.items() if v.get('type') == 'custom'}
        if custom_wordlists:
            first_custom = list(custom_wordlists.values())[0]
            analysis = wordlist_manager.analyze_wordlist_size(first_custom['path'])
            assert 'password_count' in analysis, "Analysis should include password count"
            print(f"✓ Analyzed wordlist: {analysis.get('password_count', 0)} passwords")
        
        # Test 7: Optimize wordlist
        print("\n7. Testing wordlist optimization...")
        if custom_wordlists:
            first_custom = list(custom_wordlists.values())[0]
            # Create a wordlist with duplicates for testing
            test_passwords_with_dupes = ['test1', 'test2', 'test1', 'test3', 'test2']
            success, dup_path = wordlist_manager.create_custom_wordlist(
                'test_duplicates', test_passwords_with_dupes, 'Test with duplicates'
            )
            
            if success:
                success, message, stats = wordlist_manager.optimize_wordlist(dup_path)
                assert success, f"Should optimize wordlist: {message}"
                assert stats.get('duplicates_removed', 0) > 0, "Should remove duplicates"
                print(f"✓ Optimized wordlist: removed {stats.get('duplicates_removed', 0)} duplicates")
        
        print("\n🎉 All wordlist functionality tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_wordlist_functionality()
    sys.exit(0 if success else 1)