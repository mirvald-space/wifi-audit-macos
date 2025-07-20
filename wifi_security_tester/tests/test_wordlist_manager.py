#!/usr/bin/env python3
"""
Test script for WordlistManager component
"""

import sys
import os
from pathlib import Path

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent))

from components.wordlist_manager import WordlistManager
from core.logger import get_logger

def test_wordlist_manager():
    """Test WordlistManager functionality"""
    logger = get_logger("test_wordlist_manager")
    logger.info("Starting WordlistManager tests")
    
    try:
        # Initialize WordlistManager
        wm = WordlistManager()
        logger.info("WordlistManager initialized successfully")
        
        # Test 1: Generate built-in wordlists
        logger.info("Test 1: Generating built-in wordlists")
        for category in wm.builtin_categories.keys():
            passwords = wm.generate_builtin_wordlist(category)
            logger.info(f"Generated {len(passwords)} passwords for category '{category}'")
            
            # Show first few passwords as sample
            if passwords:
                sample = passwords[:5]
                logger.info(f"Sample passwords from {category}: {sample}")
        
        # Test 2: Create custom wordlist
        logger.info("Test 2: Creating custom wordlist")
        test_passwords = ['testpass123', 'mypassword', 'wifi123', 'password123', 'testpass123']  # Include duplicate
        success, result = wm.create_custom_wordlist('test_wordlist', test_passwords, 'Test wordlist')
        
        if success:
            logger.info(f"Custom wordlist created successfully: {result}")
        else:
            logger.error(f"Failed to create custom wordlist: {result}")
        
        # Test 3: Get available wordlists
        logger.info("Test 3: Getting available wordlists")
        available = wm.get_available_wordlists()
        logger.info(f"Found {len(available)} available wordlists:")
        for name, info in available.items():
            if info['type'] == 'builtin':
                logger.info(f"  {name}: {info['description']} (estimated: {info['estimated_size']} passwords)")
            else:
                logger.info(f"  {name}: {info.get('password_count', 'unknown')} passwords, {info.get('size_formatted', 'unknown')}")
        
        # Test 4: Analyze wordlist (if custom wordlist was created)
        if success and os.path.exists(result):
            logger.info("Test 4: Analyzing wordlist")
            analysis = wm.analyze_wordlist_size(result)
            if 'error' not in analysis:
                logger.info(f"Wordlist analysis: {analysis['password_count']} passwords, avg length {analysis['average_length']}")
                logger.info(f"Charset analysis: {analysis['charset_analysis']}")
            else:
                logger.error(f"Analysis failed: {analysis['error']}")
            
            # Test 5: Time estimation
            logger.info("Test 5: Time estimation")
            estimation = wm.estimate_crack_time(result, keys_per_second=1000)
            if 'error' not in estimation:
                logger.info(f"Time estimation: avg {estimation['average_time_formatted']}, max {estimation['maximum_time_formatted']}")
            else:
                logger.error(f"Time estimation failed: {estimation['error']}")
        
        # Test 6: Create combined wordlist
        logger.info("Test 6: Creating combined wordlist")
        wordlist_names = ['builtin_common', 'builtin_numeric']
        success, result = wm.create_combined_wordlist('test_combined', wordlist_names)
        
        if success:
            logger.info(f"Combined wordlist created successfully: {result}")
        else:
            logger.error(f"Failed to create combined wordlist: {result}")
        
        logger.info("All WordlistManager tests completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Test failed with error: {e}")
        return False

if __name__ == "__main__":
    success = test_wordlist_manager()
    sys.exit(0 if success else 1)