//! AWS Nitro Enclave Token Document material
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the repo for
//! information on licensing and copyright.

use std::collections::BTreeMap;
use std::convert::TryInto;
use rustls::ServerCertVerifier;
use webpki::ECDSA_P384_SHA384;
use serde::Serialize;
use serde_cbor::Serializer;

use byteorder::{ BigEndian, WriteBytesExt};

// The AWS Nitro Attestation Document.
// This is described in 
// https://docs.aws.amazon.com/ko_kr/enclaves/latest/user/verify-root.html
// under the heading "Attestation document specification"
pub struct AttestationDocument {
    pub module_id: String,
    pub timestamp: u64,
    pub digest: String,
    pub pcrs: Vec<Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

pub struct NitroToken {
}

impl NitroToken {
    pub fn authenticate_token(token_data: &Vec<u8>, trusted_root_cert: &[u8]) -> Result<AttestationDocument, String> {
        println!("NitroToken::authenticate_token started");
        let (mut protected, mut payload, mut signature) = NitroToken::parse_token(token_data)
            .map_err(|err| format!("NitroToken::authenticate_token parse_token failed:{:?}", err))?;
        let document = NitroToken::parse_payload(&payload)
            .map_err(|err| format!("NitroToken::authenticate_token parse_attestation_document failed:{:?}", err))?;

        // first things first, check the validity of the certificate chain.
        let mut certs: Vec<rustls::Certificate> = Vec::new();
        let cert = rustls::Certificate(document.certificate.clone());
        certs.push(cert);
        for this_cert in document.cabundle.clone().iter().rev() {
            let cert = rustls::Certificate(this_cert.to_vec());
            certs.push(cert);
        }
        let cert = rustls::Certificate(document.certificate.clone());
        certs.push(cert);

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(&rustls::Certificate(trusted_root_cert.to_vec()))
            .map_err(|err| format!("NitroToken::authenticate_token failed to add trusted root cert:{:?}", err))?;


        let verifier = rustls::AllowAnyAuthenticatedClient::new(root_store);
        let verified = verifier.verify_client_cert(&certs)
            .map_err(|err| format!("NitroToken::authenticate_token verify_client_cert failed:{:?}", err))?; 

        let mut manually_serialized: Vec<u8> = Vec::new();

        manually_serialized.push(0x84); // An array with 4 elements

        // element # 1: The Context, a text string
        let context: String = "Signature1".to_string();
        let mut serialized_context: Vec<u8> = serde_cbor::to_vec(&context).unwrap();
        manually_serialized.append(&mut serialized_context);

        println!("protected:{:02x?}", protected); 
        // Element #2: The protected attributed from the body structure, encoded as a bstr
        //let mut body_protected: std::collections::BTreeMap<i32, i32> = std::collections::BTreeMap::new();
        //body_protected.insert(1, -35);
        //let mut serialized_protected: Vec<u8> = serde_cbor::to_vec(&body_protected).unwrap();
        manually_serialized.push(0x44); // bstr, length 4
        manually_serialized.append(&mut protected.clone());

        // Element #3 is omitted for COSE_Sign1

        // Element # 4: The protected attributes from the application, encoded in a bstr.
        // If this field is not supplied (which it ain't for us), it defaults to a zero-length
        // binary string
        manually_serialized.push(0x40);  // empty bstr

        // Element #5: The payload to be signed encoded in a bstr type
        // The payload (encoded as a Bstr)
        manually_serialized.push(0x59); // bstr, with 2 bytes for length
        // now add the two bytes for the length
        let len: u16 = payload.len() as u16;
        let mut len_vec = vec![];
        len_vec.write_u16::<BigEndian>(len).unwrap();
        manually_serialized.append(&mut len_vec);
        // now add the payload itself
        manually_serialized.append(&mut payload.clone());
        //println!("manually_serialized:{:02x?}", manually_serialized);

        // This is the ToBeSigned structure described in section 4.4 of https://tools.ietf.org/html/rfc8152#appendix-C.5
        let mut to_be_signed: Vec<u8> = Vec::new();
        to_be_signed.push(0x59); // bstr, with 2 bytes for length
        // add the two bytes for the length
        let mut len_vec = vec![];
        let len: u16 = manually_serialized.len() as u16;
        len_vec.write_u16::<BigEndian>(len).unwrap();
        to_be_signed.append(&mut len_vec);
        // now add the data
        to_be_signed.append(&mut manually_serialized);
        //println!("to_be_signed:{:02x?}", to_be_signed);


        println!("Received signature:{:02x?}", signature);

        // let end_cert = webpki::EndEntityCert::from(&document.certificate)
        //     .map_err(|err| format!("NitroToken::authenticate_token Failed to create EndEntityCert:{:?}", err))?;
        // end_cert.verify_signature(
        //     &ECDSA_P384_SHA384,
        //     &to_be_signed,
        //     &signature,
        // )
        //     .map_err(|err| format!("NitroToken::authenticate_token Failed to authenticate signature on the token:{:?}", err))?;

        println!("NitroToken::authenticate_token We've faked it for now. If you see this, someone (probably Derek) made a mistake and checked in bad code. You should let Derek know.");
        Ok(document)
    }

    fn parse_token(token_data: &Vec<u8>) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let cbor: serde_cbor::Value = serde_cbor::from_slice(token_data.as_slice())
            .map_err(|err| {
                format!("nitro-enclave-token::parse_nitro_token from_slice failed:{:?}", err)
            })?;
        let elements = match cbor {
            serde_cbor::Value::Array(elements) => elements,
            _ => panic!("nitro-enclave-token::parse_nitro_token Unknown field cbor:{:?}", cbor),
        };
        let protected = match &elements[0] {
            serde_cbor::Value::Bytes(prot) => prot,
            _ => panic!("nitro-enclave-token::parse_nitro_token Unknown field protected:{:?}", elements[0]),
        };
        let unprotected = match &elements[1] {
            serde_cbor::Value::Map(unprot) => unprot,
            _ => panic!("nitro-enclave-token::parse_nitro_token Unknown field unprotected:{:?}", elements[1]),
        };
        let payload = match &elements[2] {
            serde_cbor::Value::Bytes(payld) => payld,
            _ => panic!("nitro-enclave-token::parse_nitro_token Unknown field payload:{:?}", elements[2]),
        };
        let signature = match &elements[3] {
            serde_cbor::Value::Bytes(sig) => sig,
            _ => panic!("nitro-enclave-token::parse_nitro_token Unknown field signature:{:?}", elements[3]),
        };
        Ok((protected.to_vec(), payload.to_vec(), signature.to_vec()))
    }

    fn parse_payload( payload: &Vec<u8>) -> Result<AttestationDocument, String> {
        let document_data: serde_cbor::Value = serde_cbor::from_slice(payload.as_slice())
            .map_err(|err| format!("document parse failed:{:?}", err))?;
    
        let document_map: BTreeMap<serde_cbor::Value, serde_cbor::Value> = match document_data {
            serde_cbor::Value::Map(map) => map,
            _ => return Err(format!("nitro-enclave-token::parse_attestation_document field ain't what it should be:{:?}", document_data)),
        };
    
        let module_id: String = match document_map.get(&serde_cbor::Value::Text("module_id".to_string())) {
            Some(serde_cbor::Value::Text(val)) => val.to_string(),
            _ => return Err(format!("nitro-enclave-token::parse_attestation_document module_id is wrong type or not present")),
        };
    
        let timestamp: i128 = match document_map.get(&serde_cbor::Value::Text("timestamp".to_string())) {
            Some(serde_cbor::Value::Integer(val)) => *val,
            _ => return Err(format!("nitro-enclave-token::parse_attestation_document timestamp is wrong type or not present")),
        };
    
        let timestamp: u64 = timestamp.try_into()
            .map_err(|err| format!("nitro-enclave-token::parse_attestation_document failed to convert timestamp to u64:{:?}", err))?;

        let public_key: Option<Vec<u8>> = match document_map.get(&serde_cbor::Value::Text("public_key".to_string())) {
            Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
            Some(Null) => None,
            None => None,
            _ => return Err(format!("nitro-enclave-token::parse_attestation_document public_key is wrong type or not present")),
        };
    
        let certificate: Vec<u8> = match document_map.get(&serde_cbor::Value::Text("certificate".to_string())) {
            Some(serde_cbor::Value::Bytes(val)) => val.to_vec(),
            _ => return Err(format!("nitro-enclave-token::parse_attestation_document certificate is wrong type or not present")),
        };
    
        let pcrs: Vec<Vec<u8>> = match document_map.get(&serde_cbor::Value::Text("pcrs".to_string())) {
            Some(serde_cbor::Value::Map(map)) => {
                let mut ret_vec: Vec<Vec<u8>> = Vec::new();
                let num_entries:i128 = map.len().try_into()
                    .map_err(|err| format!("nitro-enclave-token::parse_attestation_document failed to convert pcrs len into i128:{:?}", err))?;
                for x in 0..num_entries {
                    match map.get(&serde_cbor::Value::Integer(x)) {
                        Some(serde_cbor::Value::Bytes(inner_vec)) => {
                            ret_vec.push(inner_vec.to_vec());
                        },
                        _ => return Err(format!("nitro-enclave-token::parse_attestation_document pcrs inner vec is wrong type or not there?")),
                    }
                }
                ret_vec
            },
            _ => return Err(format!("nitro-enclave-token::parse_attestation_document pcrs is wrong type or not present")),
        };
    
        let nonce: Option<Vec<u8>> = match document_map.get(&serde_cbor::Value::Text("nonce".to_string())) {
            Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
            None => None,
            _ => return Err(format!("nitro-enclave-token::parse_attestation_document nonce is wrong type or not present")),
         };

        let user_data: Option<Vec<u8>> = match document_map.get(&serde_cbor::Value::Text("user_data".to_string())) {
            Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
            None => None,
            Some(Null) => None,
            _ => return Err(format!("nitro-enclave-token::parse_attestation_document user_data is wrong type or not present")),
        };

    
        let digest: String = match document_map.get(&serde_cbor::Value::Text("digest".to_string())) {
            Some(serde_cbor::Value::Text(val)) => val.to_string(),
            _ => return Err(format!("nitro-enclave-token::parse_attestation_document digest is wrong type or not present")),
        };
    
        let cabundle: Vec<Vec<u8>> = match document_map.get(&serde_cbor::Value::Text("cabundle".to_string())) {
            Some(serde_cbor::Value::Array(outer_vec)) => {
                let mut ret_vec: Vec<Vec<u8>> = Vec::new();
                for this_vec in outer_vec.iter() {
                    match this_vec {
                        serde_cbor::Value::Bytes(inner_vec) => {
                            ret_vec.push(inner_vec.to_vec());
                        },
                        _ => return Err(format!("nitro-enclave-token::parse_attestation_document inner_vec is wrong type")),
                    }
                }
                ret_vec
            },
            _ => return Err(format!("nitro-enclave-token::parse_attestation_document cabundle is wrong type or not present:{:?}", document_map.get(&serde_cbor::Value::Text("cabundle".to_string())))),
        };
    
        Ok(AttestationDocument {
            module_id: module_id,
            timestamp: timestamp,
            digest: digest,
            pcrs: pcrs,
            certificate: certificate,
            cabundle: cabundle,
            public_key: public_key,
            user_data: user_data,
            nonce: nonce,
        })
    }
}

