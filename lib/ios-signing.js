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
const path = require("path");
const core = require("@actions/core");
const io = require("@actions/io");
const exec = require('@actions/exec');
const ioutils = require("./io-utils");
/**
 * Creates a temporary keychain and installs the P12 cert in the temporary keychain
 * @param keychainPath the path to the keychain file
 * @param keychainPwd the password to use for unlocking the keychain
 * @param p12CertPath the P12 cert to be installed in the keychain
 * @param p12Pwd the password for the P12 cert
 * @param useKeychainIfExists Pass false to delete and recreate a preexisting keychain
 */
function installCertInTemporaryKeychain(keychainPath, keychainPwd, p12CertPath, p12Pwd, useKeychainIfExists) {
    return __awaiter(this, void 0, void 0, function* () {
        let setupKeychain = true;
        if (useKeychainIfExists && ioutils.exists(keychainPath)) {
            setupKeychain = false;
        }
        let securityCmd = yield io.which('security', true);
        if (setupKeychain) {
            //delete keychain if exists
            yield deleteKeychain(keychainPath);
            //create keychain
            yield exec.exec(securityCmd, ['create-keychain', '-p', keychainPwd, keychainPath]);
            //update keychain settings, keep keychain unlocked for 6h = 21600 sec, which is the job timeout for paid hosted VMs
            yield exec.exec(securityCmd, ['set-keychain-settings', '-lut', '21600', keychainPath]);
        }
        //unlock keychain
        yield unlockKeychain(keychainPath, keychainPwd);
        //import p12 cert into the keychain
        if (!p12Pwd) {
            // if password is null or not defined, set it to empty
            p12Pwd = '';
        }
        yield exec.exec(securityCmd, ['import', p12CertPath, '-P', p12Pwd, '-A', '-t', 'cert', '-f', 'pkcs12', '-k', keychainPath]);
        //If we imported into a pre-existing keychain (e.g. login.keychain), set the partition_id ACL for the private key we just imported
        //so codesign won't prompt to use the key for signing. This isn't necessary for temporary keychains, at least on High Sierra.
        //See https://stackoverflow.com/questions/39868578/security-codesign-in-sierra-keychain-ignores-access-control-settings-and-ui-p
        if (!setupKeychain) {
            const privateKeyName = yield getP12PrivateKeyName(p12CertPath, p12Pwd);
            yield setKeyPartitionList(keychainPath, keychainPwd, privateKeyName);
        }
        //list the keychains to get current keychains in search path
        let listAllOutput;
        const listAllOpts = {};
        listAllOpts.listeners = {
            stdout: (data) => {
                if (data) {
                    if (listAllOutput) {
                        listAllOutput = listAllOutput.concat(data.toString().trim());
                    }
                    else {
                        listAllOutput = data.toString().trim();
                    }
                }
            }
        };
        yield exec.exec(securityCmd, ['list-keychain', '-d', 'user'], listAllOpts);
        let allKeychainsArr = [];
        core.debug('listAllOutput = ' + listAllOutput);
        //parse out all the existing keychains in search path
        if (listAllOutput) {
            allKeychainsArr = listAllOutput.split(/[\n\r\f\v]/gm);
        }
        //add the keychain to list path along with existing keychains if it is not in the path
        if (listAllOutput && listAllOutput.indexOf(keychainPath) < 0) {
            let listAddArgs = ['list-keychain', '-d', 'user', '-s', keychainPath];
            for (var i = 0; i < allKeychainsArr.length; i++) {
                listAddArgs.push(allKeychainsArr[i].trim().replace(/"/gm, ''));
            }
            yield exec.exec(securityCmd, listAddArgs);
        }
        let listVerifyOutput;
        const listVerifyOpts = {};
        listVerifyOpts.listeners = {
            stdout: (data) => {
                if (data) {
                    if (listVerifyOutput) {
                        listVerifyOutput = listVerifyOutput.concat(data.toString().trim());
                    }
                    else {
                        listVerifyOutput = data.toString().trim();
                    }
                }
            }
        };
        yield exec.exec(securityCmd, ['list-keychain', '-d', 'user'], listVerifyOpts);
        if (!listVerifyOutput || listVerifyOutput.indexOf(keychainPath) < 0) {
            throw ('TempKeychainSetupFailed');
        }
    });
}
exports.installCertInTemporaryKeychain = installCertInTemporaryKeychain;
/**
 * Finds an iOS codesigning identity in the specified keychain
 * @param keychainPath
 * @returns {string} signing identity found
 */
function findSigningIdentity(keychainPath) {
    return __awaiter(this, void 0, void 0, function* () {
        let signIdentity;
        let securityCmd = yield io.which('security', true);
        const findIdentityOpts = {};
        findIdentityOpts.listeners = {
            stdout: (data) => {
                if (data) {
                    let matches = data.toString().trim().match(/"(.+)"/g);
                    core.debug('signing identity data = ' + matches);
                    if (matches && matches[0]) {
                        signIdentity = matches[0].replace(/"/gm, '');
                        core.debug('signing identity data trimmed = ' + signIdentity);
                    }
                }
            }
        };
        yield exec.exec(securityCmd, ['find-identity', '-v', '-p', 'codesigning', keychainPath], findIdentityOpts);
        if (signIdentity) {
            core.debug('findSigningIdentity = ' + signIdentity);
            return signIdentity;
        }
        else {
            throw ('SignIdNotFound');
        }
    });
}
exports.findSigningIdentity = findSigningIdentity;
/**
 * Get Cloud entitlement type Production or Development according to the export method - if entitlement doesn't exists in provisioning profile returns null
 * @param provisioningProfilePath
 * @param exportMethod
 * @returns {string}
 */
function getCloudEntitlement(provisioningProfilePath, exportMethod) {
    return __awaiter(this, void 0, void 0, function* () {
        //find the provisioning profile details
        let tmpPlist = '_xcodetasktmp.plist';
        yield saveProvisioningProfileDetails(provisioningProfilePath, tmpPlist);
        //use PlistBuddy to figure out if cloud entitlement exists.
        const cloudEntitlement = yield execPlistBuddyCommand('Print Entitlements:com.apple.developer.icloud-container-environment', tmpPlist);
        //delete the temporary plist file
        yield io.rmRF(tmpPlist);
        if (!cloudEntitlement) {
            return null;
        }
        core.debug('Provisioning Profile contains cloud entitlement');
        return (exportMethod === 'app-store' || exportMethod === 'enterprise' || exportMethod === 'developer-id')
            ? "Production"
            : "Development";
    });
}
exports.getCloudEntitlement = getCloudEntitlement;
/**
 * Find the UUID and Name of the provisioning profile and install the profile
 * @param provProfilePath
 * @returns { provProfileUUID, provProfileName }
 */
function installProvisioningProfile(provProfilePath) {
    return __awaiter(this, void 0, void 0, function* () {
        //find the provisioning profile UUID
        let tmpPlist = '_xcodetasktmp.plist';
        yield saveProvisioningProfileDetails(provProfilePath, tmpPlist);
        //use PlistBuddy to figure out the UUID and Name
        let provProfileUUID = yield execPlistBuddyCommand('Print UUID', tmpPlist);
        let provProfileName = yield execPlistBuddyCommand('Print Name', tmpPlist);
        //delete the temporary plist file
        yield io.rmRF(tmpPlist);
        if (provProfileUUID) {
            //copy the provisioning profile file to ~/Library/MobileDevice/Provisioning Profiles
            io.mkdirP(getUserProvisioningProfilesPath()); // Path may not exist if Xcode has not been run yet.
            core.debug('created directory: ' + getUserProvisioningProfilesPath());
            let pathToProvProfile = getProvisioningProfilePath(provProfileUUID, provProfilePath);
            core.debug('copying provisioning profile to destination: ' + pathToProvProfile);
            let cpCmd = yield io.which('cp', true);
            let cpArgs = ['-f', provProfilePath, pathToProvProfile];
            yield exec.exec(cpCmd, cpArgs);
            if (!provProfileName) {
                core.warning('ProvProfileNameNotFound');
                provProfileName = '';
            }
            return { provProfileUUID, provProfileName };
        }
        else {
            throw new Error('ProvProfileUUIDNotFound: ' + provProfilePath);
        }
    });
}
exports.installProvisioningProfile = installProvisioningProfile;
/**
 * Find the Name of the provisioning profile
 * @param provProfilePath
 * @returns {string} Name
 */
function getProvisioningProfileName(provProfilePath) {
    return __awaiter(this, void 0, void 0, function* () {
        //find the provisioning profile UUID
        let tmpPlist = '_xcodetasktmp.plist';
        let provProfileDetails = yield saveProvisioningProfileDetails(provProfilePath, tmpPlist);
        //use PlistBuddy to figure out the Name
        let provProfileName = yield execPlistBuddyCommand('Print Name', tmpPlist);
        //delete the temporary plist file
        yield io.rmRF(tmpPlist);
        core.debug('getProvisioningProfileName: profile name = ' + provProfileName);
        return provProfileName;
    });
}
exports.getProvisioningProfileName = getProvisioningProfileName;
/**
 * Find the type of the iOS provisioning profile - app-store, ad-hoc, enterprise or development
 * @param provProfilePath
 * @returns {string} type
 */
function getiOSProvisioningProfileType(provProfilePath) {
    return __awaiter(this, void 0, void 0, function* () {
        let provProfileType;
        try {
            //find the provisioning profile details
            let tmpPlist = '_xcodetasktmp.plist';
            yield saveProvisioningProfileDetails(provProfilePath, tmpPlist);
            //get ProvisionsAllDevices - this will exist for enterprise profiles
            let provisionsAllDevices = yield execPlistBuddyCommand('Print ProvisionsAllDevices', tmpPlist);
            core.debug('provisionsAllDevices = ' + provisionsAllDevices);
            if (provisionsAllDevices && provisionsAllDevices.trim().toLowerCase() === 'true') {
                //ProvisionsAllDevices = true in enterprise profiles
                provProfileType = 'enterprise';
            }
            else {
                let getTaskAllow = yield execPlistBuddyCommand('Print Entitlements:get-task-allow', tmpPlist);
                core.debug('getTaskAllow = ' + getTaskAllow);
                if (getTaskAllow && getTaskAllow.trim().toLowerCase() === 'true') {
                    //get-task-allow = true means it is a development profile
                    provProfileType = 'development';
                }
                else {
                    let provisionedDevices = yield execPlistBuddyCommand('Print ProvisionedDevices', tmpPlist);
                    core.debug('provisionedDevices = ' + provisionedDevices);
                    if (!provisionedDevices) {
                        // no provisioned devices for non-development profile means it is an app-store profile
                        provProfileType = 'app-store';
                    }
                    else {
                        // non-development profile with provisioned devices - use ad-hoc
                        provProfileType = 'ad-hoc';
                    }
                }
            }
            //delete the temporary plist file
            yield io.rmRF(tmpPlist);
        }
        catch (err) {
            core.debug(err);
        }
        return provProfileType;
    });
}
exports.getiOSProvisioningProfileType = getiOSProvisioningProfileType;
/**
 * Find the type of the macOS provisioning profile - app-store, developer-id or development.
 * mac-application is a fourth macOS export method, but it doesn't include signing.
 * @param provProfilePath
 * @returns {string} type
 */
function getmacOSProvisioningProfileType(provProfilePath) {
    return __awaiter(this, void 0, void 0, function* () {
        let provProfileType;
        try {
            //find the provisioning profile details
            let tmpPlist = '_xcodetasktmp.plist';
            yield saveProvisioningProfileDetails(provProfilePath, tmpPlist);
            //get ProvisionsAllDevices - this will exist for developer-id profiles
            let provisionsAllDevices = yield execPlistBuddyCommand('Print ProvisionsAllDevices', tmpPlist);
            core.debug('provisionsAllDevices = ' + provisionsAllDevices);
            if (provisionsAllDevices && provisionsAllDevices.trim().toLowerCase() === 'true') {
                //ProvisionsAllDevices = true in developer-id profiles
                provProfileType = 'developer-id';
            }
            else {
                let provisionedDevices = yield execPlistBuddyCommand('Print ProvisionedDevices', tmpPlist);
                if (!provisionedDevices) {
                    // no provisioned devices means it is an app-store profile
                    provProfileType = 'app-store';
                }
                else {
                    // profile with provisioned devices - use development
                    provProfileType = 'development';
                }
            }
            //delete the temporary plist file
            yield io.rmRF(tmpPlist);
        }
        catch (err) {
            core.debug(err);
        }
        return provProfileType;
    });
}
exports.getmacOSProvisioningProfileType = getmacOSProvisioningProfileType;
/**
 * Unlock specified iOS keychain
 * @param keychainPath
 * @param keychainPwd
 */
function unlockKeychain(keychainPath, keychainPwd) {
    return __awaiter(this, void 0, void 0, function* () {
        //unlock the keychain
        let unlockCommand = yield io.which('security', true);
        yield exec.exec(unlockCommand, ['unlock-keychain', '-p', keychainPwd, keychainPath]);
    });
}
exports.unlockKeychain = unlockKeychain;
/**
 * Delete specified iOS keychain
 * @param keychainPath
 */
function deleteKeychain(keychainPath) {
    return __awaiter(this, void 0, void 0, function* () {
        if (ioutils.exists(keychainPath)) {
            let deleteKeychainCommand = yield io.which('security', true);
            yield exec.exec(deleteKeychainCommand, ['delete-keychain', keychainPath]);
        }
    });
}
exports.deleteKeychain = deleteKeychain;
/**
 * Delete provisioning profile with specified UUID in the user's profiles directory
 * @param uuid
 */
function deleteProvisioningProfile(uuid) {
    return __awaiter(this, void 0, void 0, function* () {
        if (uuid && uuid.trim()) {
            let findCmd = yield io.which('ls', true);
            let provProfilesDir = getUserProvisioningProfilesPath();
            let findArgs = ['-1', provProfilesDir + '/' + uuid.trim() + '*'];
            const findOpts = {};
            findOpts.listeners = {
                stdline: (data) => __awaiter(this, void 0, void 0, function* () {
                    let profPath = provProfilesDir + '/' + data;
                    if (ioutils.exists(profPath)) {
                        console.log('Deleting provisioning profile: ' + profPath);
                        yield io.rmRF(profPath);
                    }
                })
            };
            yield exec.exec(findCmd, findArgs, findOpts);
        }
    });
}
exports.deleteProvisioningProfile = deleteProvisioningProfile;
/**
 * Gets the path to the iOS default keychain
 */
function getDefaultKeychainPath() {
    return __awaiter(this, void 0, void 0, function* () {
        let defaultKeychainPath = '';
        let getKeychainCmd = yield io.which('security', true);
        const getKeyChainOpts = {};
        getKeyChainOpts.listeners = {
            stdout: (data) => {
                if (data) {
                    defaultKeychainPath = data.toString().trim().replace(/[",\n\r\f\v]/gm, '');
                    if (!ioutils.exists(defaultKeychainPath)) {
                        throw new Error('Received invalid default keychain path.');
                    }
                }
            }
        };
        yield exec.exec(getKeychainCmd, ['default-keychain'], getKeyChainOpts);
        return defaultKeychainPath;
    });
}
exports.getDefaultKeychainPath = getDefaultKeychainPath;
/**
 * Gets the path to the temporary keychain path used during build or release
 */
function getTempKeychainPath() {
    let keychainName = 'ios_signing_temp.keychain';
    let getTempKeychainPath = path.resolve('/tmp', keychainName);
    return getTempKeychainPath;
}
exports.getTempKeychainPath = getTempKeychainPath;
/**
 * Get several x509 properties from the certificate in a P12 file.
 * @param p12Path Path to the P12 file
 * @param p12Pwd Password for the P12 file
 */
function getP12Properties(p12Path, p12Pwd) {
    return __awaiter(this, void 0, void 0, function* () {
        //openssl pkcs12 -in <p12Path> -nokeys -passin pass:"<p12Pwd>" | openssl x509 -noout -fingerprint –subject -dates    
        let output = '';
        if (!p12Pwd) {
            // if password is null or not defined, set it to empty
            p12Pwd = '';
        }
        let fingerprint;
        let commonName;
        let notBefore;
        let notAfter;
        function onLine(line) {
            if (line) {
                const tuple = splitIntoKeyValue(line);
                const key = (tuple) ? tuple.key : '';
                const value = (tuple) ? tuple.value : '';
                if (key === 'SHA1 Fingerprint') {
                    // Example value: "BB:26:83:C6:AA:88:35:DE:36:94:F2:CF:37:0A:D4:60:BB:AE:87:0C"
                    // Remove colons separating each octet.
                    fingerprint = value.replace(/:/g, '').trim();
                }
                else if (key === 'subject') {
                    // Example value: "/UID=E848ASUQZY/CN=iPhone Developer: Chris Sidi (7RZ3N927YF)/OU=DJ8T2973U7/O=Chris Sidi/C=US"
                    // Extract the common name.
                    const matches = value.match(/\/CN=([^/]+)/);
                    if (matches && matches[1]) {
                        commonName = matches[1].trim();
                    }
                }
                else if (key === 'notBefore') {
                    // Example value: "Nov 13 03:37:42 2018 GMT"
                    notBefore = new Date(value);
                }
                else if (key === 'notAfter') {
                    notAfter = new Date(value);
                }
            }
        }
        let opensslcmd = yield io.which('openssl', true);
        yield exec.exec(opensslcmd, ['pkcs12', '-in', p12Path, '-out', '/tmp/step1.openssl', '-nokeys', '-passin', 'pass:' + p12Pwd]);
        const opensslopts = {};
        opensslopts.listeners = {
            stdout: (data) => {
                output = output + data.toString();
            }
        };
        try {
            yield exec.exec(opensslcmd, ['x509', '-in', '/tmp/step1.openssl', '-noout', '-fingerprint', '-subject', '-dates'], opensslopts);
            // process the collected stdout.
            let line;
            for (line of output.split('\n')) {
                onLine(line);
            }
        }
        catch (err) {
            if (!p12Pwd) {
                core.warning('NoP12PwdWarning');
            }
            throw err;
        }
        core.debug(`P12 fingerprint: ${fingerprint}`);
        core.debug(`P12 common name (CN): ${commonName}`);
        core.debug(`NotBefore: ${notBefore}`);
        core.debug(`NotAfter: ${notAfter}`);
        return { fingerprint, commonName, notBefore, notAfter };
    });
}
exports.getP12Properties = getP12Properties;
/**
 * Get the friendly name from the private key in a P12 file.
 * @param p12Path Path to the P12 file
 * @param p12Pwd Password for the P12 file
 */
function getP12PrivateKeyName(p12Path, p12Pwd) {
    return __awaiter(this, void 0, void 0, function* () {
        //openssl pkcs12 -in <p12Path> -nocerts -passin pass:"<p12Pwd>" -passout pass:"<p12Pwd>" | grep 'friendlyName'
        core.debug('getting the P12 private key name');
        if (!p12Pwd) {
            // if password is null or not defined, set it to empty
            p12Pwd = '';
        }
        // since we can't suppress the private key bytes, encrypt them before we pass them to grep.
        const privateKeyPassword = p12Pwd ? p12Pwd : generatePassword();
        let privateKeyName;
        const opensslPathCmd = yield io.which('openssl', true);
        //we pipe through grep so we we don't log the private key to the console.
        //even if it's encrypted, it's noise and could cause concern for some users.
        const grepCmd = yield io.which('grep', true);
        yield exec.exec(opensslPathCmd, ['pkcs12', '-in', p12Path, '-out', '/tmp/p12privkeyname.tmp', '-nocerts', '-passin', 'pass:' + p12Pwd, '-passout', 'pass:' + privateKeyPassword]);
        const grepOpts = {};
        grepOpts.listeners = {
            stdout: (data) => {
                if (data) {
                    // find the private key name
                    let trimmedData = data.toString().trim();
                    const match = trimmedData.match(/friendlyName: (.*)/);
                    if (match && match[1]) {
                        privateKeyName = match[1].trim();
                    }
                }
            }
        };
        yield exec.exec(grepCmd, ['friendlyName', '/tmp/p12privkeyname.tmp'], grepOpts);
        core.debug('P12 private key name = ' + privateKeyName);
        if (!privateKeyName) {
            throw new Error('P12PrivateKeyNameNotFound: ' + p12Path);
        }
        return privateKeyName;
    });
}
exports.getP12PrivateKeyName = getP12PrivateKeyName;
/**
 * Set the partition_id ACL so codesign has permission to use the signing key.
 */
function setKeyPartitionList(keychainPath, keychainPwd, privateKeyName) {
    return __awaiter(this, void 0, void 0, function* () {
        // security set-key-partition-list -S apple-tool:,apple: -s -l <privateKeyName> -k <keychainPwd> <keychainPath>
        // n.b. This command could update multiple keys (e.g. an expired signing key and a newer signing key.)
        if (privateKeyName) {
            core.debug(`Setting the partition_id ACL for ${privateKeyName}`);
            // "If you'd like to run /usr/bin/codesign with the key, "apple:" must be an element of the partition list." - security(1) man page.
            // When you sign into your developer account in Xcode on a new machine, you get a private key with partition list "apple:". However
            // "security import a.p12 -k login.keychain" results in the private key with partition list "apple-tool:". I'm preserving import's
            // "apple-tool:" and adding the "apple:" codesign needs.
            const partitionList = 'apple-tool:,apple:';
            let setKeyCommand = yield io.which('security', true);
            let setKeyArgs = ['set-key-partition-list', '-S', partitionList, '-s', '-l', privateKeyName, '-k', keychainPwd, keychainPath];
            let unknownCommandErrorFound = false;
            let incorrectPasswordErrorFound;
            const setKeyOpts = {};
            // Watch for "unknown command". set-key-partition-list was added in Sierra (macOS v10.12)
            setKeyOpts.listeners = {
                errline: (line) => {
                    if (!unknownCommandErrorFound && line.includes('security: unknown command')) {
                        unknownCommandErrorFound = true;
                    }
                }
            };
            try {
                yield exec.exec(setKeyCommand, setKeyArgs, setKeyOpts);
            }
            catch (err) {
                if (unknownCommandErrorFound) {
                    // If we're on an older OS, we don't need to run set-key-partition-list.
                    console.log('SetKeyPartitionListCommandNotFound');
                }
                else {
                    core.error(err);
                    throw new Error('SetKeyPartitionListCommandFailed');
                }
            }
        }
    });
}
function getUserProvisioningProfilesPath() {
    core.debug('getUserProvisioningProfilesPath()');
    return path.resolve(process.env['HOME'] || '/', 'Library', 'MobileDevice', 'Provisioning Profiles');
}
function getProvisioningProfilePath(uuid, provProfilePath) {
    let profileExtension = '';
    if (provProfilePath) {
        profileExtension = path.extname(provProfilePath);
    }
    return path.resolve(getUserProvisioningProfilesPath(), uuid.trim().concat(profileExtension));
}
function generatePassword() {
    return Math.random().toString(36);
}
function splitIntoKeyValue(line) {
    // Don't use `split`. The value may contain `=` (e.g. "/UID=E848ASUQZY/CN=iPhone Developer: ...")
    const index = line.indexOf('=');
    if (index) {
        return { key: line.substring(0, index), value: line.substring(index + 1) };
    }
    else {
        return undefined;
    }
}
function getProvisioningProfileDetails(profProfilePath) {
    return __awaiter(this, void 0, void 0, function* () {
        core.debug('getProvisioningProfileDetails()');
        if (ioutils.exists(profProfilePath)) {
            let securityCmd = yield io.which('security', true);
            let provProfileDetails;
            const getCloudOpts = {};
            getCloudOpts.listeners = {
                stdout: (data) => {
                    if (data) {
                        if (provProfileDetails) {
                            provProfileDetails = provProfileDetails.concat(data.toString().trim().replace(/[,\n\r\f\v]/gm, ''));
                        }
                        else {
                            provProfileDetails = data.toString().trim().replace(/[,\n\r\f\v]/gm, '');
                        }
                    }
                }
            };
            yield exec.exec(securityCmd, ['cms', '-D', '-i', profProfilePath], getCloudOpts);
            core.debug('called security cms -D -i ' + profProfilePath);
            return provProfileDetails;
        }
        else {
            core.error('supplied provisioning profile path does not exist.');
            throw new Error('ProvProfileNotFound');
        }
    });
}
function saveProvisioningProfileDetails(profProfilePath, writeToFile) {
    return __awaiter(this, void 0, void 0, function* () {
        core.debug('saveProvisioningProfileDetails()');
        let details = yield getProvisioningProfileDetails(profProfilePath);
        if (details) {
            //write the provisioning profile to a plist
            ioutils.writeFile(writeToFile, details);
            core.debug('wrote provisioning profile as plist to ' + writeToFile);
        }
        else {
            throw new Error('ProvProfileDetailsNotFound: ' + profProfilePath);
        }
        return details;
    });
}
function execPlistBuddyCommand(command, plistfile) {
    return __awaiter(this, void 0, void 0, function* () {
        let results;
        let plistCmd = yield io.which('/usr/libexec/PlistBuddy', true);
        let plistArgs = ['-c', command, plistfile];
        const plistOpts = {};
        plistOpts.listeners = {
            stdout: (data) => {
                if (data) {
                    results = data.toString().trim();
                }
            }
        };
        yield exec.exec(plistCmd, plistArgs, plistOpts);
        return results;
    });
}
