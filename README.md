# Install iOS Signing Certificate

Use this action to install an Apple certificate during your iOS build. The certificate is automatically removed post-build.

## Setup

This action requires that your certificate be BASE64 encoded and placed in a secret in your project's GitHub repository.

To encode your profile, export your certificate as a P12 file.

```
base64 -i YOUR_CERT.p12 -o CERT_FILENAME.base64
```

Then copy the contents of CERT_FILENAME.base64 to a secret (ex: P12CERTIFICATE) in your mobile apps' GitHub repostitory. 

## Usage

In your project's action worksflow, add the install certificate step prior to your app's build step.

```
    steps:
    - name: Install certificate
      uses: mobileactions/install-ios-certificate@v1
      with:
        encoded-certificate: ${{ secrets.P12CERTIFICATE }}
```
