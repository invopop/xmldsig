# Test Certificates

Source of `facturae.p12` file: https://github.com/josemmo/Facturae-PHP

Which in turn is sourced from https://ws024.juntadeandalucia.es/ae/adminelec/areatecnica/afirma and issued with the name: "EIDAS_CERTIFICADO_PRUEBAS\_\_\_99999999R".

Go does not support BER encoded certificates, thus the certificate needs to be extract and re-saved under the p12 format, which according to the tool used, will provide files in DER encoding.

Apple's "Keychain Access" tool works well for this. First import that original `.p12` file, then export the generated certificate and private key together from Keychain using the p12 format option and probably a new password.

## .pfx certificate

Certificate in `cert-20260102-131809.pfx` is a self-signed certificate usable for testing integration with KSeF.

Note that it expires in 1 year from the date it was created. It will be necessary to generate a new one after that date, and update the tests with the new file name.
