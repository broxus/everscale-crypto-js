use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;
use hmac::{Mac, NewMac};
use pbkdf2::pbkdf2;
use rand::Rng;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use zeroize::Zeroize;

#[wasm_bindgen(typescript_custom_section)]
const KEYPAIR: &str = r#"
export type KeyPair = {
    secretKey: string,
    publicKey: string,
};

export type ExtendedSignature = {
    signature: string,
    signatureHex: string,
    signatureParts: {
        high: string,
        low: string,
    }
};
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "KeyPair")]
    pub type JsKeyPair;

    #[wasm_bindgen(typescript_type = "ExtendedSignature")]
    pub type JsExtendedSignature;
}

const LANGUAGE: bip39::Language = bip39::Language::English;

#[wasm_bindgen(js_name = "generateLegacyPhrase")]
pub fn generate_legacy() -> String {
    use bip39::util::{Bits11, IterExt};

    #[inline(always)]
    fn sha256_first_byte(input: &[u8]) -> u8 {
        use sha2::Digest;
        sha2::Sha256::digest(input)[0]
    }

    let entropy: [u8; 32] = rand::thread_rng().gen();
    let checksum_byte = sha256_first_byte(&entropy);

    let wordlist = LANGUAGE.wordlist();

    entropy
        .iter()
        .chain(Some(&checksum_byte))
        .bits()
        .map(|bits: Bits11| wordlist.get_word(bits))
        .join(" ")
}

#[wasm_bindgen(js_name = "deriveLegacyPhrase")]
pub fn derive_legacy_phrase(phrase: &str) -> Result<JsKeyPair, JsValue> {
    const PBKDF_ITERATIONS: u32 = 100_000;
    const SALT: &[u8] = b"TON default seed";

    let phrase = phrase.trim();

    let wordmap = LANGUAGE.wordmap();
    let mut word_count = 0;
    for word in phrase.split_whitespace() {
        word_count += 1;
        if word_count > 24 {
            return Err("Expected 24 words").handle_error();
        }

        wordmap.get_bits(word).handle_error()?;
    }
    if word_count != 24 {
        return Err("Expected 24 words").handle_error();
    }

    let password = hmac::Hmac::<sha2::Sha512>::new_from_slice(phrase.as_bytes())
        .unwrap()
        .finalize()
        .into_bytes();

    let mut res = [0; 512 / 8];
    pbkdf2::<hmac::Hmac<sha2::Sha512>>(&password, SALT, PBKDF_ITERATIONS, &mut res);

    let secret = ed25519_dalek::SecretKey::from_bytes(&res[0..32]).unwrap();
    let public = ed25519_dalek::PublicKey::from(&secret);

    Ok(ObjectBuilder::new()
        .set("secretKey", hex::encode(secret.as_bytes()))
        .set("publicKey", hex::encode(public.as_bytes()))
        .build()
        .unchecked_into())
}

#[wasm_bindgen(js_name = "generateBip39Phrase")]
pub fn generate_bip39_phrase(words: u8) -> Result<String, JsValue> {
    let mnemonic_type = bip39::MnemonicType::for_word_count(words as usize).handle_error()?;
    Ok(bip39::Mnemonic::new(mnemonic_type, LANGUAGE).to_string())
}

#[wasm_bindgen(js_name = "deriveBip39Phrase")]
pub fn derive_bip39_phrase(phrase: &str, path: &str) -> Result<JsKeyPair, JsValue> {
    let mnemonic = bip39::Mnemonic::from_phrase(phrase.trim(), LANGUAGE).handle_error()?;
    let hd = bip39::Seed::new(&mnemonic, "");
    let seed_bytes = hd.as_bytes();

    let derived = tiny_hderive::bip32::ExtendedPrivKey::derive(seed_bytes, path)
        .map_err(|_| "Invalid derivation path")?;

    let secret = ed25519_dalek::SecretKey::from_bytes(&derived.secret()).expect("Shouldn't fail");
    let public = ed25519_dalek::PublicKey::from(&secret);

    Ok(ObjectBuilder::new()
        .set("secretKey", hex::encode(secret.as_bytes()))
        .set("publicKey", hex::encode(public.as_bytes()))
        .build()
        .unchecked_into())
}

#[wasm_bindgen(js_name = "makeBip39Path")]
pub fn make_bip39_path(account_id: u16) -> String {
    format!("m/44'/396'/0'/0/{account_id}")
}

#[wasm_bindgen(js_name = "sign")]
pub fn sign(secret_key: &str, data: &str) -> Result<String, JsValue> {
    let data = parse_hex_or_base64_bytes(data).handle_error()?;

    let mut secret_key = parse_hex_or_base64_bytes(secret_key).handle_error()?;
    let secret = ed25519_dalek::SecretKey::from_bytes(&secret_key).handle_error()?;
    secret_key.zeroize();

    let public = ed25519_dalek::PublicKey::from(&secret);
    let key_pair = ed25519_dalek::Keypair { secret, public };
    let signature = key_pair.sign(&data);
    Ok(base64::encode(signature.to_bytes()))
}

#[wasm_bindgen(js_name = "getPublicKey")]
pub fn get_public_key(secret_key: &str) -> Result<String, JsValue> {
    let mut secret_key = parse_hex_or_base64_bytes(secret_key).handle_error()?;
    let secret = ed25519_dalek::SecretKey::from_bytes(&secret_key).handle_error()?;
    secret_key.zeroize();

    let public = ed25519_dalek::PublicKey::from(&secret);
    Ok(hex::encode(public.as_bytes()))
}

#[wasm_bindgen(js_name = "verifySignature")]
pub fn verify_signature(public_key: &str, data: &str, signature: &str) -> Result<bool, JsValue> {
    let public_key = parse_public_key(public_key)?;

    let data = parse_hex_or_base64_bytes(data).handle_error()?;
    let signature = parse_signature(signature)?;

    Ok(public_key.verify(&data, &signature).is_ok())
}

#[wasm_bindgen(js_name = "extendSignature")]
pub fn extend_signature(signature: &str) -> Result<JsExtendedSignature, JsValue> {
    let signature = parse_signature(signature)?;
    Ok(make_extended_signature(signature.to_bytes()))
}

pub fn make_extended_signature(signature: [u8; 64]) -> JsExtendedSignature {
    ObjectBuilder::new()
        .set("signature", base64::encode(signature))
        .set("signatureHex", hex::encode(signature))
        .set(
            "signatureParts",
            ObjectBuilder::new()
                .set("high", format!("0x{}", hex::encode(&signature[..32])))
                .set("low", format!("0x{}", hex::encode(&signature[32..])))
                .build(),
        )
        .build()
        .unchecked_into()
}

fn parse_signature(signature: &str) -> Result<ed25519_dalek::Signature, JsValue> {
    let signature = parse_hex_or_base64_bytes(signature).handle_error()?;
    match ed25519_dalek::Signature::try_from(signature.as_slice()) {
        Ok(signature) => Ok(signature),
        Err(_) => Err("Invalid signature. Expected 64 bytes").handle_error(),
    }
}

pub fn parse_public_key(public_key: &str) -> Result<ed25519_dalek::PublicKey, JsValue> {
    ed25519_dalek::PublicKey::from_bytes(&parse_hex_bytes(public_key.trim()).handle_error()?)
        .handle_error()
}

fn parse_hex_or_base64_bytes(data: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let data = data.trim();
    if data.is_empty() {
        return Ok(Default::default());
    }

    match parse_hex_bytes(data) {
        Ok(signature) => Ok(signature),
        Err(e) => match base64::decode(data) {
            Ok(signature) => Ok(signature),
            Err(_) => Err(e),
        },
    }
}

fn parse_hex_bytes(data: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(data.strip_prefix("0x").unwrap_or(data))
}

pub trait HandleError {
    type Output;

    fn handle_error(self) -> Result<Self::Output, JsValue>;
}

impl<T, E> HandleError for Result<T, E>
where
    E: ToString,
{
    type Output = T;

    fn handle_error(self) -> Result<Self::Output, JsValue> {
        self.map_err(|e| {
            let error = e.to_string();
            js_sys::Error::new(&error).unchecked_into()
        })
    }
}

pub struct ObjectBuilder {
    object: js_sys::Object,
}

impl ObjectBuilder {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            object: js_sys::Object::new(),
        }
    }

    pub fn set<T>(self, key: &str, value: T) -> Self
    where
        JsValue: From<T>,
    {
        let key = JsValue::from_str(key);
        let value = JsValue::from(value);
        js_sys::Reflect::set(&self.object, &key, &value).expect("Shouldn't fail");
        self
    }

    #[inline(always)]
    pub fn build(self) -> JsValue {
        JsValue::from(self.object)
    }
}

impl Default for ObjectBuilder {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}
