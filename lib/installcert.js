"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const os = require("os");
const core = require("@actions/core");
const io = require("@actions/io");
const exec = require('@actions/exec');
const sign = require("./ios-signing");
const fs = require("fs");
function run() {
    return __awaiter(this, void 0, void 0, function* () {
        yield installSigningCertTask();
    });
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
function installSigningCertTask() {
    return __awaiter(this, void 0, void 0, function* () {
        // Check platform is macOS since demands are not evaluated on Hosted pools
        if (os.platform() !== 'darwin') {
            throw new Error('InstallRequiresMac');
        }
        // download decrypted contents
        let encodedSigningCertData = core.getInput('encoded-certificate');
        let inputRequired = {};
        inputRequired.required = true;
        let keychain = core.getInput('keychain', inputRequired);
        let keychainPwd = core.getInput('keychainPassword');
        let certPwd = core.getInput('certificate-password', inputRequired);
        const commonNameOverride = core.getInput('certSigningIdentity');
        let tempCertFile = '/tmp/cert.base64';
        let signingCertFile = '/tmp/cert.p12';
        try {
            if (encodedSigningCertData) {
                fs.writeFile(tempCertFile, encodedSigningCertData, (err) => __awaiter(this, void 0, void 0, function* () {
                    if (err) {
                        core.error('could not write base64 signing cert file to /tmp');
                    }
                    else {
                        let base64Cmd = yield io.which('base64', true);
                        yield exec.exec(base64Cmd, ['-d', '-i', tempCertFile, '-o', signingCertFile]);
                        // remove base64 file
                        io.rmRF(tempCertFile);
                        core.debug('Removed base64 version of signing certificate.');
                        // get the P12 details - SHA1 hash, common name (CN) and expiration.
                        const p12Properties = yield sign.getP12Properties(signingCertFile, certPwd);
                        let commonName = p12Properties.commonName;
                        const fingerprint = p12Properties.fingerprint, notBefore = p12Properties.notBefore, notAfter = p12Properties.notAfter;
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
                        const now = new Date();
                        if (!notBefore || !notAfter) {
                            throw new Error('Certificate dates are invalid or undefined.');
                        }
                        if (notBefore > now || notAfter < now) {
                            throw new Error('Certificate dates are invalid.');
                        }
                        // install the certificate in specified keychain, keychain is created if required
                        let keychainPath;
                        if (keychain === 'temp') {
                            keychainPath = sign.getTempKeychainPath();
                            // generate a keychain password for the temporary keychain
                            // overriding any value we may have read because keychainPassword is hidden in the designer for 'temp'.
                            keychainPwd = Math.random().toString(36);
                            core.exportVariable('keychainPassword', keychainPwd);
                        }
                        else if (keychain === 'default') {
                            keychainPath = yield sign.getDefaultKeychainPath();
                        }
                        else if (keychain === 'custom') {
                            keychainPath = core.getInput('customKeychainPath', inputRequired);
                        }
                        else {
                            throw new Error('Unable to set location for keychain.');
                        }
                        core.exportVariable('APPLE_CERTIFICATE_KEYCHAIN', keychainPath);
                        yield sign.installCertInTemporaryKeychain(keychainPath, keychainPwd, signingCertFile, certPwd, true);
                        // set the keychain output variable.
                        core.exportVariable('keychainPath', keychainPath);
                        // Set the legacy variables that doesn't use the task's refName, unlike our output variables.
                        // If there are multiple InstallAppleCertificate tasks, the last one wins.
                        core.exportVariable('APPLE_CERTIFICATE_SIGNING_IDENTITY', commonName);
                        core.exportVariable('APPLE_CERTIFICATE_KEYCHAIN', keychainPath);
                    }
                }));
            }
            else {
                core.error('Secret containing BASE64 of P12 cert not valid, or contents invalid.');
                core.setFailed('Contents of P12 invalid.');
            }
        }
        catch (err) {
            core.setFailed(err);
        }
        finally {
            // delete certificate from temp location after installing
            io.rmRF(tempCertFile);
            io.rmRF(signingCertFile);
        }
    });
}
exports.installSigningCertTask = installSigningCertTask;
run();
