//! AWS Nitro Enclave Document material
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

impl AttestationDocument {
    pub fn authenticate(
        document_data: &[u8],
        trusted_root_cert: &[u8],
    ) -> Result<Self, String> {
        // Following the steps here: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
        // Step 1. Decode the CBOR object and map it to a COSE_Sign1 structure
        let (_protected, payload, _signature) =
            AttestationDocument::parse(document_data).map_err(|err| {
                format!(
                    "AttestationDocument::authenticate parse failed:{:?}",
                    err
                )
            })?;
        // Step 2. Exract the attestation document from the COSE_Sign1 structure
        let document = AttestationDocument::parse_payload(&payload).map_err(|err| {
            format!(
                "AttestationDocument::authenticate failed:{:?}",
                err
            )
        })?;

        // Step 3. Verify the certificate's chain
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
        root_store
            .add(&rustls::Certificate(trusted_root_cert.to_vec()))
            .map_err(|err| {
                format!(
                    "AttestationDocument::authenticate failed to add trusted root cert:{:?}",
                    err
                )
            })?;

        let verifier = rustls::AllowAnyAuthenticatedClient::new(root_store);
        let _verified = verifier.verify_client_cert(&certs).map_err(|err| {
            format!(
                "AttestationDocument::authenticate verify_client_cert failed:{:?}",
                err
            )
        })?;
        // if verify_client_cert didn't generate an error, authentication passed

        // Step 4. Ensure the attestation document is properly signed
        let authenticated = {
            let sig_structure = aws_nitro_enclaves_cose::sign::COSESign1::from_bytes(document_data)
                .map_err(|err| {
                    format!("AttestationDocument::authenticate failed to load document_data as COSESign1 structure:{:?}", err)
                })?;
            let cert = openssl::x509::X509::from_der(&document.certificate)
                .map_err(|err| {
                    format!("AttestationDocument::authenticate failed to parse document.certificate as X509 certificate:{:?}", err)
                })?;
            let public_key = cert.public_key()
                .map_err(|err| {
                    format!("AttestationDocument::authenticate failed to extract public key from certificate:{:?}", err)
                })?;
            let pub_ec_key = public_key.ec_key().map_err(|err| {
                format!(
                    "AttestationDocument::authenticate failed to get ec_key from public_key:{:?}",
                    err
                )
            })?;
            let result = sig_structure.verify_signature(&pub_ec_key)
                .map_err(|err| {
                    format!("AttestationDocument::authenticate failed to verify signature on sig_structure:{:?}", err)
                })?;
            result
        };
        if !authenticated {
            return Err(format!(
                "AttestationDocument::authenticate invalid COSE certificate for provided key"
            ));
        } else {
            return Ok(document);
        }
    }

    fn parse(document_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let cbor: serde_cbor::Value =
            serde_cbor::from_slice(document_data).map_err(|err| {
                format!(
                    "AttestationDocument::parse from_slice failed:{:?}",
                    err
                )
            })?;
        let elements = match cbor {
            serde_cbor::Value::Array(elements) => elements,
            _ => panic!(
                "AttestationDocument::parse Unknown field cbor:{:?}",
                cbor
            ),
        };
        let protected = match &elements[0] {
            serde_cbor::Value::Bytes(prot) => prot,
            _ => panic!(
                "AttestationDocument::parse Unknown field protected:{:?}",
                elements[0]
            ),
        };
        let _unprotected = match &elements[1] {
            serde_cbor::Value::Map(unprot) => unprot,
            _ => panic!(
                "AttestationDocument::parse Unknown field unprotected:{:?}",
                elements[1]
            ),
        };
        let payload = match &elements[2] {
            serde_cbor::Value::Bytes(payld) => payld,
            _ => panic!(
                "AttestationDocument::parse Unknown field payload:{:?}",
                elements[2]
            ),
        };
        let signature = match &elements[3] {
            serde_cbor::Value::Bytes(sig) => sig,
            _ => panic!(
                "AttestationDocument::parse Unknown field signature:{:?}",
                elements[3]
            ),
        };
        Ok((protected.to_vec(), payload.to_vec(), signature.to_vec()))
    }

    fn parse_payload(payload: &Vec<u8>) -> Result<AttestationDocument, String> {
        let document_data: serde_cbor::Value = serde_cbor::from_slice(payload.as_slice())
            .map_err(|err| format!("document parse failed:{:?}", err))?;

        let document_map: BTreeMap<serde_cbor::Value, serde_cbor::Value> = match document_data {
            serde_cbor::Value::Map(map) => map,
            _ => return Err(format!("AttestationDocument::parse_payload field ain't what it should be:{:?}", document_data)),
        };

        let module_id: String = match document_map.get(&serde_cbor::Value::Text("module_id".to_string())) {
            Some(serde_cbor::Value::Text(val)) => val.to_string(),
            _ => return Err(format!("AttestationDocument::parse_payload module_id is wrong type or not present")),
        };

        let timestamp: i128 = match document_map.get(&serde_cbor::Value::Text("timestamp".to_string())) {
            Some(serde_cbor::Value::Integer(val)) => *val,
            _ => return Err(format!("AttestationDocument::parse_payload timestamp is wrong type or not present")),
        };

        let timestamp: u64 = timestamp.try_into()
            .map_err(|err| format!("AttestationDocument::parse_payload failed to convert timestamp to u64:{:?}", err))?;

        let public_key: Option<Vec<u8>> =
            match document_map.get(&serde_cbor::Value::Text("public_key".to_string())) {
                Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
                Some(_null) => None,
                None => None,
            };

        let certificate: Vec<u8> = match document_map.get(&serde_cbor::Value::Text("certificate".to_string())) {
            Some(serde_cbor::Value::Bytes(val)) => val.to_vec(),
            _ => return Err(format!("AttestationDocument::parse_payload certificate is wrong type or not present")),
        };

        let pcrs: Vec<Vec<u8>> = match document_map
            .get(&serde_cbor::Value::Text("pcrs".to_string()))
        {
            Some(serde_cbor::Value::Map(map)) => {
                let mut ret_vec: Vec<Vec<u8>> = Vec::new();
                let num_entries:i128 = map.len().try_into()
                    .map_err(|err| format!("AttestationDocument::parse_payload failed to convert pcrs len into i128:{:?}", err))?;
                for x in 0..num_entries {
                    match map.get(&serde_cbor::Value::Integer(x)) {
                        Some(serde_cbor::Value::Bytes(inner_vec)) => {
                            ret_vec.push(inner_vec.to_vec());
                        },
                        _ => return Err(format!("AttestationDocument::parse_payload pcrs inner vec is wrong type or not there?")),
                    }
                }
                ret_vec
            }
            _ => return Err(format!(
                "AttestationDocument::parse_payload pcrs is wrong type or not present"
            )),
        };

        let nonce: Option<Vec<u8>> = match document_map.get(&serde_cbor::Value::Text("nonce".to_string())) {
            Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
            None => None,
            _ => return Err(format!("AttestationDocument::parse_payload nonce is wrong type or not present")),
         };

        let user_data: Option<Vec<u8>> =
            match document_map.get(&serde_cbor::Value::Text("user_data".to_string())) {
                Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
                None => None,
                Some(_null) => None,
            };

        let digest: String = match document_map.get(&serde_cbor::Value::Text("digest".to_string())) {
            Some(serde_cbor::Value::Text(val)) => val.to_string(),
            _ => return Err(format!("AttestationDocument::parse_payload digest is wrong type or not present")),
        };

        let cabundle: Vec<Vec<u8>> = match document_map.get(&serde_cbor::Value::Text("cabundle".to_string())) {
            Some(serde_cbor::Value::Array(outer_vec)) => {
                let mut ret_vec: Vec<Vec<u8>> = Vec::new();
                for this_vec in outer_vec.iter() {
                    match this_vec {
                        serde_cbor::Value::Bytes(inner_vec) => {
                            ret_vec.push(inner_vec.to_vec());
                        },
                        _ => return Err(format!("AttestationDocument::parse_payload inner_vec is wrong type")),
                    }
                }
                ret_vec
            },
            _ => return Err(format!("AttestationDocument::parse_payload cabundle is wrong type or not present:{:?}", document_map.get(&serde_cbor::Value::Text("cabundle".to_string())))),
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
