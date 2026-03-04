#!/usr/bin/env python3
"""
Quick test: call get_user_products for a sample user and print results.
Run from repo root: python tools/test_get_products.py
"""
import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from controllers import auth

# Try with user_id 1 (adjust if needed)
user_id = 1
products = auth.get_user_products(user_id)
print('Products for user', user_id)
for p in products:
    print(p)

print('Total:', len(products))
