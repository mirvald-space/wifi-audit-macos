#!/usr/bin/env python3
"""
Test script for wordlist management menu integration
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent / "wifi_security_tester"
sys.path.insert(0, str(project_root))

from core.menu_system import MenuSystem
from components.wordlist_manager import WordlistManager

def test_wordlist_integration():
    """Test wordlist manager integration with menu system"""
    print("Testing wordlist management integration...")
    
    try:
        # Test WordlistManager initialization
        wordlist_manager = WordlistManager()
        print("✓ WordlistManager initialized successfully")
        
        # Test MenuSystem initialization with wordlist manager
        menu_system = MenuSystem()
        print("✓ MenuSystem initialized with wordlist manager")
        
        # Test that wordlist manager is accessible
        assert hasattr(menu_system, 'wordlist_manager'), "Menu system should have wordlist_manager attribute"
        print("✓ WordlistManager accessible from menu system")
        
        # Test menu items include wordlist management
        menu_items = menu_system.menu_items
        assert "6" in menu_items, "Menu should have option 6"
        assert "Wordlist Management" in menu_items["6"]["title"], "Option 6 should be wordlist management"
        print("✓ Wordlist management menu option present")
        
        # Test wordlist handler exists
        handler = menu_items["6"]["handler"]
        assert callable(handler), "Wordlist handler should be callable"
        assert handler.__name__ == "_wordlist_management_handler", "Should have correct handler method"
        print("✓ Wordlist management handler correctly assigned")
        
        # Test available wordlists functionality
        wordlists = wordlist_manager.get_available_wordlists()
        print(f"✓ Found {len(wordlists)} available wordlists")
        
        # Test built-in wordlist generation
        categories = wordlist_manager.builtin_categories
        print(f"✓ {len(categories)} built-in categories available: {list(categories.keys())}")
        
        # Test generating a small built-in wordlist
        common_passwords = wordlist_manager.generate_builtin_wordlist('common')
        print(f"✓ Generated {len(common_passwords)} common passwords")
        
        print("\n🎉 All wordlist management integration tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_wordlist_integration()
    sys.exit(0 if success else 1)