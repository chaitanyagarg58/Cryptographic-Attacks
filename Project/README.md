# Project README

## Environment Requirements
- **Python Version:** 3.8.10
- **Libraries Used:** 
  - `pwntools`
  - `random`
  - `string`

Please ensure that the correct Python version is used. If "python3" corresponds to the given version, take either of the following actions:
1. Install `python-is-python3`.
2. Replace "python" with "python3" in line 5 of both `attack.py` files, and also use `python3` instead of `python` in all subsequent commands.

## Attack 1: Linear Feedback Shift Register (LFSR)

**lfsr_server.py:** Implements the encryption algorithm and provides the necessary oracles for the attack.  
**Usage:** Run using `python lfsr_server.py`.

**lfsr_attack.py:** Utilizes the `pwntools` library to communicate with `lfsr_server.py` and execute the attack.  
**Usage:** Run using `python lfsr_attack.py`.

## Attack 2: RC4 in WEP

**wep_rc4_server.py:** Implements the encryption algorithm and provides the required oracles for the attack.  
**Usage:** Run using `python wep_rc4_server.py`.

**wep_rc4_attack.py:** Utilizes the `pwntools` library to communicate with `wep_rc4_server.py` and perform the attack.  
**Usage:** Run using `python wep_rc4_attack.py`.

## GitHub Repository
- The Codebase can be accessed at this [GitHub Repository](https://github.com/chaitanyagarg58/Attacks-on-Stream-Cipher).