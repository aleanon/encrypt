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
encrypt = { git = "https://github.com/aleanon/encrypt.git", version = "0.1.0" }
```

Or write this in your terminal:

cargo add --git "https://github.com/aleanon/encrypt.git"

## Example

Here's how to implement encryption for a custom type:

```rust

use encrypt::{
    traits::Encrypt,
    Error,
    algorithms::AES256GCM,
};

// Your type that needs encryption
#[derive(Debug)]
struct SecretMessage {
    content: String,
}

// Implement the Encrypt trait
impl Encrypt for SecretMessage {
    type Error = Error;  // Use the built-in error type
    type AlgorithmType = AES256GCM;  // Choose encryption algorithm

    // Convert your data to bytes for encryption
    fn data_to_encrypt(&self) -> Result<impl Into<Vec<u8>>, Self::Error> {
        Ok(self.content.as_bytes().to_vec())
    }

    // Convert decrypted bytes back to your type
    fn from_decrypted_data(data: &[u8]) -> Result<Self, Self::Error> {
        let content = String::from_utf8(data.to_vec())
            .map_err(|_| Error::FailedToParseDecryptedData)?;
        
        Ok(Self { content })
    }
}

// Example usage
fn main() -> Result<(), Error> {
    let message = SecretMessage {
        content: "Hello, World!".to_string(),
    };

    // Encrypt the message
    let mut encrypted = message.encrypt_with_secret("my-secret-password")?;

    // Decrypt the message
    let decrypted = encrypted.decrypt_with_secret("my-secret-password")?;
    assert_eq!(decrypted.content, "Hello, World!");

    // You can also pre-generate key and salt for reuse
    let key_salt = SecretMessage::create_new_key_salt_pair("my-secret-password")?;
    
    let encrypted = message.encrypt_with_key_salt_pair(key_salt)?;
    Ok(())
}
```

## Advanced Usage

### Custom Key Iterations

You can customize the number of key derivation iterations by overriding the `KEY_ITERATIONS` constant:

```rust
!#[doc(test(attr(ignore)))]

use encrypt::traits::Encrypt;

#[derive(Debug)]
struct SecretMessage {
    content: String,
}

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

use encrypt::{
    traits::Encrypt,
    Error,
    algorithms::{
        AES128GCM, AES256GCM,
        chacha::CHACHA20POLY1305,
    },
};

// Example type
struct SecretData;

impl Encrypt for SecretData {
    type Error = Error;
    
    // AES-128-GCM for faster encryption with good security
    type AlgorithmType = AES128GCM;
    
    // ... rest of implementation
}

// Or use AES-256-GCM for maximum security
impl Encrypt for SecretData {
    type Error = Error;
    type AlgorithmType = AES256GCM;
    // ...
}

// Or ChaCha20-Poly1305 for good performance on platforms without AES hardware
impl Encrypt for SecretData {
    type Error = Error;
    type AlgorithmType = CHACHA20POLY1305;
    // ...
}
```

## Security Notes

- The library uses secure defaults:
  - 600,000 iterations for key derivation
  - Automatic salt generation
  - Authenticated encryption (AEAD)
- Key material is automatically zeroized when dropped
- Built on the [ring](https://github.com/briansmith/ring) cryptography library

## License

This project is licensed under the MIT License.
