# encrypt

A safe and easy-to-use encryption library for Rust that provides trait-based encryption/decryption functionality with support for multiple algorithms.

## Features

- Simple trait-based interface for encryption/decryption
- Support for multiple encryption algorithms:
  - AES-128-GCM
  - AES-256-GCM
  - ChaCha20-Poly1305
- Secure key derivation with configurable iteration count
- Automatic salt generation and management
- Built on top of the [ring](https://github.com/briansmith/ring) cryptography library

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
encrypt = "0.1.0"
```

## Example

Here's how to implement encryption for a custom type:

```rust
use encrypt::{
    Encrypt,
    algorithms::AES256GCM,
    CryptoError,
};

// Your type that needs encryption
#[derive(Debug)]
struct SecretMessage {
    content: String,
}

// Implement the Encrypt trait
impl Encrypt for SecretMessage {
    type Error = CryptoError;  // Use the built-in error type
    type AlgorithmType = AES256GCM;  // Choose encryption algorithm

    // Convert your data to bytes for encryption
    fn data_to_encrypt(&self) -> Result<impl Into<Vec<u8>>, Self::Error> {
        Ok(self.content.as_bytes().to_vec())
    }

    // Convert decrypted bytes back to your type
    fn from_decrypted_data(data: &[u8]) -> Result<Self, Self::Error> {
        let content = String::from_utf8(data.to_vec())
            .map_err(|_| CryptoError::FailedToDecryptData)?;
        
        Ok(Self { content })
    }
}

// Example usage
fn main() -> Result<(), CryptoError> {
    let message = SecretMessage {
        content: "Hello, World!".to_string(),
    };

    // Encrypt the message
    let encrypted = message.encrypt("my-secret-password")?;

    // Decrypt the message
    let decrypted = encrypted.decrypt("my-secret-password")?;
    assert_eq!(decrypted.content, "Hello, World!");

    // You can also pre-generate key and salt for reuse
    let key_salt = SecretMessage::create_key_and_salt("my-secret-password")?;
    
    let encrypted = message.encrypt_with_key_and_salt(key_salt)?;

    Ok(())
}
```

## Advanced Usage

### Custom Key Iterations

You can customize the number of key derivation iterations by overriding the `KEY_ITERATIONS` constant:

```rust
use std::num::NonZeroU32;

impl Encrypt for SecretMessage {
    // ... other trait items ...
    
    // Override for more secure but slower key derivation
    const KEY_ITERATIONS: NonZeroU32 = NonZeroU32::new(1_000_000).unwrap();
}
```

### Different Algorithms

Choose from available algorithms based on your security needs:

```rust
// AES-128-GCM for faster encryption with good security
type AlgorithmType = AES128GCM;

// AES-256-GCM for maximum security
type AlgorithmType = AES256GCM;

// ChaCha20-Poly1305 for good performance on platforms without AES hardware acceleration
type AlgorithmType = CHACHA20POLY1305;
```

## Security Notes

- The library uses secure defaults:
  - 600,000 iterations for key derivation
  - Automatic salt generation
  - Authenticated encryption (AEAD)
- Key material is automatically zeroized when dropped
- Built on the audited [ring](https://github.com/briansmith/ring) cryptography library

## License

This project is licensed under the MIT License.
