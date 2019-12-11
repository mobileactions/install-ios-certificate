import os = require('os');
import core = require('@actions/core');
import io = require('@actions/io');
const exec = require('@actions/exec');
import ioutils = require('./io-utils');
import sign = require('./ios-signing');
import fs = require('fs');
import path = require('path');
import { coerce } from 'semver';


async function run() {
   await installSigningCertTask();
}

/**
 * Installs iOS signing certificate
 * Requires environment variables set from task input:
 * P12_CERTIFICATE - BASE64 encoded P12 certificate (required)
 * CERTPWD - password to P12 (required)
 * KEYCHAIN - temp, default, or custom (required)
 * KEYCHAINPWD - password to keychain (not required using temp keychain)
 * CERTSIGNINGIDENTITY - Override common name (not required)
 */
export async function installSigningCertTask() {

    // Check platform is macOS since demands are not evaluated on Hosted pools
    if (os.platform() !== 'darwin') {
        throw new Error('InstallRequiresMac');
    }

    // download decrypted contents
    let encodedSigningCertData = core.getInput('encoded-certificate');

    let inputRequired: core.InputOptions = {};
    inputRequired.required = true;
    let keychain: string = core.getInput('keychain', inputRequired);
    let keychainPwd: string = core.getInput('keychainPassword');
    let certPwd: string = core.getInput('certificate-password', inputRequired);
    const commonNameOverride: string = core.getInput('certSigningIdentity');

    let tempCertFile = '/tmp/cert.base64';
    let signingCertFile = '/tmp/cert.p12';


    try {
        if (encodedSigningCertData) {
            fs.writeFile(tempCertFile, encodedSigningCertData, async (err) => {
                if (err) {
                    core.error('could not write base64 signing cert file to /tmp');
                }
                else {
                    let base64Cmd = await io.which('base64', true);
                    await exec.exec(base64Cmd, ['-d', '-i', tempCertFile, '-o', signingCertFile]);

                    // remove base64 file
                    io.rmRF(tempCertFile);
                    core.debug('Removed base64 version of signing certificate.');

                    // get the P12 details - SHA1 hash, common name (CN) and expiration.
                    const p12Properties = await sign.getP12Properties(signingCertFile, certPwd);
                    let commonName: string | undefined = p12Properties.commonName;
                    const fingerprint: string | undefined = p12Properties.fingerprint,
                        notBefore: Date | undefined = p12Properties.notBefore,
                        notAfter: Date | undefined = p12Properties.notAfter;
                    
                    // give user an option to override the CN as a workaround if we can't parse the certificate's subject.
                    if (commonNameOverride) {
                        commonName = commonNameOverride;
                    }

                    if (!fingerprint || !commonName) {
                        throw new Error('INVALID_P12');
                    }
                    core.exportVariable('APPLE_CERTIFICATE_SHA1HASH', fingerprint);
                    core.exportVariable('signingIdentity', commonName);
            
                    // Warn if the certificate is not yet valid or expired. If the dates are undefined or invalid, the comparisons below will return false.
                    const now: Date = new Date();
                    if (!notBefore || !notAfter) {
                        throw new Error('Certificate dates are invalid or undefined.');
                    }
                    if (notBefore > now || notAfter < now) {
                        throw new Error('Certificate dates are invalid.');
                    }

                    // install the certificate in specified keychain, keychain is created if required
                    let keychainPath: string;
                    if (keychain === 'temp') {
                        keychainPath = sign.getTempKeychainPath();
                        // generate a keychain password for the temporary keychain
                        // overriding any value we may have read because keychainPassword is hidden in the designer for 'temp'.
                        keychainPwd = Math.random().toString(36);

                        core.exportVariable('keychainPassword', keychainPwd);
                    } else if (keychain === 'default') {
                        keychainPath = await sign.getDefaultKeychainPath();
                    } else if (keychain === 'custom') {
                        keychainPath = core.getInput('customKeychainPath', inputRequired);
                    } else {
                        throw new Error('Unable to set location for keychain.');
                    }
                    core.exportVariable('APPLE_CERTIFICATE_KEYCHAIN', keychainPath);

                    await sign.installCertInTemporaryKeychain(keychainPath, keychainPwd, signingCertFile, certPwd, true);

                    // set the keychain output variable.
                    core.exportVariable('keychainPath', keychainPath);

                    // Set the legacy variables that doesn't use the task's refName, unlike our output variables.
                    // If there are multiple InstallAppleCertificate tasks, the last one wins.
                    core.exportVariable('APPLE_CERTIFICATE_SIGNING_IDENTITY', commonName);
                    core.exportVariable('APPLE_CERTIFICATE_KEYCHAIN', keychainPath);

                    // delete certificate from temp location after installing
                    io.rmRF(tempCertFile);
                    io.rmRF(signingCertFile);
                }
            });
            
        
        } else {
            core.error('Secret containing BASE64 of P12 cert not valid, or contents invalid.');
            core.setFailed('Contents of P12 invalid.');
        } 
    } catch (err) {
        core.setFailed(err);
    } finally {
        
    }
}

run();