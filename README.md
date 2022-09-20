# nitro-enclave-attestation-document
You, yes! You can authenticate and parse AWS Nitro Enclave Attestation documents!

You probably have questions.

Like, what are AWS Nitro Enclaves? Here's some info: https://aws.amazon.com/ec2/nitro/nitro-enclaves/

Also, what are AWS Nitro Enclave Attestation Documents? Here's some more info: https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html

and here's some more: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html

Now that you've read every word on those links (yeah, right), here's how to use this crate.

When you receive an attestation document (as `[u8]`), call:
```
let document = match AttestationDocument::authenticate(&document_data, &trusted_root_certificate) {
  Ok(doc) => {
    // signature of document authenticated and the data parsed correctly
    doc
    },
  Err(err) => {
    // signature of document did not authenticate, or the data was poorly formed
    // Do something with the error here
    panic!("error");
  }
}
```
You should fetch the AWS Nitro Root Certificate from this link here: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip

That link gives you the certificate in PEM format. The `authenticate` function above requires the certificate in DER format. Converting from PEM to DER is left as an exercise for the reader.

This crate is intended for use from rust projects. If you need support in another language, that is mostly left up to the reader. However, we have also implemented this functionality for the go programming language, available here: https://github.com/veracruz-project/go-nitro-enclave-attestation-document
