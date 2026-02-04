# 📖 Security Glossary

Common terms used in SolShield AI and Solana security.

---

## A

**Account Confusion**  
When two accounts of the same type can be swapped in a transaction, leading to unintended behavior.

**Anchor**  
A framework for building Solana programs with safety features like automatic account validation.

**ATA (Associated Token Account)**  
A deterministically derived token account for a wallet, following a standard PDA pattern.

**Authority**  
An account (usually a signer) that has permission to perform certain operations.

---

## B

**Bump**  
A single byte (0-255) used to derive a valid PDA from seeds that would otherwise produce an invalid address.

**Bump Seed Canonicalization**  
Using the canonical (first valid) bump for PDAs. Using non-canonical bumps can lead to collisions.

---

## C

**CPI (Cross-Program Invocation)**  
When one Solana program calls another program.

**CPI Guard**  
Protection against user-controlled accounts being passed to CPI calls.

---

## D

**Discriminator**  
An 8-byte identifier at the start of Anchor account data that identifies the account type.

---

## F

**Flash Loan**  
Borrowing assets within a single transaction, manipulating state, then repaying. Can exploit price-dependent logic.

---

## I

**Integer Overflow/Underflow**  
When arithmetic exceeds the maximum or minimum value of an integer type, wrapping around.

---

## O

**Oracle**  
An external data source (e.g., price feed). Can be manipulated if not properly validated.

**Owner Check**  
Verifying that an account is owned by the expected program.

---

## P

**PDA (Program Derived Address)**  
An address derived from seeds and a program ID, owned by that program. Cannot be signed externally.

---

## R

**Reentrancy**  
When a CPI call allows an attacker to re-enter the calling program before state changes are complete.

**Rent**  
SOL required to keep accounts alive on Solana. Accounts below rent-exemption threshold may be deleted.

---

## S

**SARIF (Static Analysis Results Interchange Format)**  
A standard JSON format for static analysis results, used by GitHub Code Scanning.

**Signer Check**  
Verifying that an account has signed the transaction.

**Staleness Check**  
Verifying that oracle data is recent enough to be trusted.

---

## T

**TWAP (Time-Weighted Average Price)**  
An average price over time, resistant to flash manipulation.

**Type Cosplay**  
When an account of one type is passed where another type is expected, exploiting deserialization.

---

## U

**Unchecked Arithmetic**  
Arithmetic operations that don't check for overflow/underflow, using wrapping behavior.

---

## V

**Verification (CPI)**  
Checking a program's audit status via cross-program invocation before interacting with it.

---

*For more details on any pattern, run `SolShield AI list` or see [PATTERNS.md](PATTERNS.md).*
